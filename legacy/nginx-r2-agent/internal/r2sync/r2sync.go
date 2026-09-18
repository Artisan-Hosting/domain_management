package r2sync

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type Client struct {
	S3     *s3.Client
	Bucket string
}

func New(ctx context.Context, endpoint, bucket string) (*Client, error) {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion("auto"))
	if err != nil {
		return nil, fmt.Errorf("loading AWS config: %w", err)
	}
	cl := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(endpoint)
		o.UsePathStyle = true
	})
	return &Client{S3: cl, Bucket: bucket}, nil
}

func (c *Client) GetObjectString(ctx context.Context, key string) (string, error) {
	out, err := c.S3.GetObject(ctx, &s3.GetObjectInput{Bucket: &c.Bucket, Key: &key})
	if err != nil {
		return "", err
	}
	defer out.Body.Close()
	b, err := io.ReadAll(out.Body)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func (c *Client) PutObjectString(ctx context.Context, key, value string) error {
	_, err := c.S3.PutObject(ctx, &s3.PutObjectInput{
		Bucket: &c.Bucket,
		Key:    &key,
		Body:   strings.NewReader(value),
	})
	return err
}

func (c *Client) PutFile(ctx context.Context, key, localPath string) error {
	f, err := os.Open(localPath)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = c.S3.PutObject(ctx, &s3.PutObjectInput{Bucket: &c.Bucket, Key: &key, Body: f})
	return err
}

type remoteObject struct {
	Key  string
	ETag string
	Size int64
}

func (c *Client) listTree(ctx context.Context, prefix string) (map[string]remoteObject, error) {
	objs := map[string]remoteObject{}
	var token *string
	for {
		out, err := c.S3.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
			Bucket:            &c.Bucket,
			Prefix:            aws.String(prefix + "/"),
			ContinuationToken: token,
		})
		if err != nil {
			return nil, err
		}
		for _, o := range out.Contents {
			rel := strings.TrimPrefix(*o.Key, prefix+"/")
			if rel == "" {
				continue
			}
			objs[rel] = remoteObject{
				Key:  *o.Key,
				ETag: strings.Trim(aws.ToString(o.ETag), `"`),
				Size: aws.ToInt64(o.Size),
			}
		}
		if out.IsTruncated == nil || !*out.IsTruncated {
			break
		}
		token = out.NextContinuationToken
	}
	return objs, nil
}

func localMD5(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := md5.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (c *Client) DownloadTree(ctx context.Context, remotePrefix, localDir string) error {
	remote, err := c.listTree(ctx, remotePrefix)
	if err != nil {
		return fmt.Errorf("listing s3://%s/%s: %w", c.Bucket, remotePrefix, err)
	}
	if err := os.MkdirAll(localDir, 0o755); err != nil {
		return err
	}

	for rel, obj := range remote {
		localPath := filepath.Join(localDir, filepath.FromSlash(rel))
		needsDownload := true
		if info, err := os.Stat(localPath); err == nil && info.Size() == obj.Size {
			if sum, err := localMD5(localPath); err == nil && sum == obj.ETag {
				needsDownload = false
			}
		}
		if !needsDownload {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(localPath), 0o755); err != nil {
			return err
		}
		out, err := c.S3.GetObject(ctx, &s3.GetObjectInput{Bucket: &c.Bucket, Key: &obj.Key})
		if err != nil {
			return fmt.Errorf("downloading %s: %w", obj.Key, err)
		}
		f, err := os.Create(localPath)
		if err != nil {
			out.Body.Close()
			return err
		}
		_, err = io.Copy(f, out.Body)
		out.Body.Close()
		f.Close()
		if err != nil {
			return fmt.Errorf("writing %s: %w", localPath, err)
		}
	}

	return filepath.WalkDir(localDir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(localDir, path)
		rel = filepath.ToSlash(rel)
		if _, ok := remote[rel]; !ok {
			_ = os.Remove(path)
		}
		return nil
	})
}

func (c *Client) UploadTree(ctx context.Context, localDir, remotePrefix string) error {
	remote, err := c.listTree(ctx, remotePrefix)
	if err != nil {
		return fmt.Errorf("listing s3://%s/%s: %w", c.Bucket, remotePrefix, err)
	}
	seen := map[string]bool{}

	walkErr := filepath.WalkDir(localDir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(localDir, path)
		rel = filepath.ToSlash(rel)
		seen[rel] = true

		info, err := d.Info()
		if err != nil {
			return err
		}
		sum, err := localMD5(path)
		if err != nil {
			return err
		}
		if obj, ok := remote[rel]; ok && obj.Size == info.Size() && obj.ETag == sum {
			return nil
		}

		key := remotePrefix + "/" + rel
		return c.PutFile(ctx, key, path)
	})
	if walkErr != nil {
		return walkErr
	}

	for rel, obj := range remote {
		if !seen[rel] {
			key := obj.Key
			if _, err := c.S3.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &c.Bucket, Key: &key}); err != nil {
				return fmt.Errorf("deleting stale %s: %w", key, err)
			}
		}
	}
	return nil
}
