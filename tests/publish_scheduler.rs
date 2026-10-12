use ais_domains::publish::scheduler::{Action, PublishScheduler};






// case A5_single_publish_after_burst_success begin
#[test]
fn case_A5_single_publish_after_burst_success() {
    let mut s = PublishScheduler::default();
    s.on_request(0);
    s.on_request(10);
    s.on_request(20);
    s.on_request(30);
    s.on_request(40);
    s.tick(100);
    s.on_started();
    s.on_finished(101, true);
    assert_eq!(s.tick(200), Action::None);
}
// case A5_single_publish_after_burst_success end

// case A5_single_publish_after_burst_success_later begin
#[test]
fn case_A5_single_publish_after_burst_success_later() {
    let mut s = PublishScheduler::default();
    s.on_request(0);
    s.on_request(10);
    s.on_request(20);
    s.on_request(30);
    s.on_request(40);
    s.tick(100);
    s.on_started();
    s.on_finished(101, true);
    assert_eq!(s.tick(1000), Action::None);
}
// case A5_single_publish_after_burst_success_later end

// case A5_single_publish_after_burst_success_new_request_after_publish begin
#[test]
fn case_A5_single_publish_after_burst_success_new_request_after_publish() {
    let mut s = PublishScheduler::default();
    s.on_request(0);
    s.on_request(10);
    s.on_request(20);
    s.on_request(30);
    s.on_request(40);
    s.tick(100);
    s.on_started();
    s.on_finished(101, true);
    s.on_request(250);
    assert_eq!(s.tick(310), Action::Publish);
}
// case A5_single_publish_after_burst_success_new_request_after_publish end

// case A6_running_tick_no_publish begin
#[test]
fn case_A6_running_tick_no_publish() {
    let mut s = PublishScheduler::default();
    s.on_request(0);
    s.tick(60);
    s.on_started();
    assert_eq!(s.tick(70), Action::None);
}
// case A6_running_tick_no_publish end

// case A6_running_tick_new_request_during_publish begin
#[test]
fn case_A6_running_tick_new_request_during_publish() {
    let mut s = PublishScheduler::default();
    s.on_request(0);
    s.tick(60);
    s.on_started();
    s.on_request(70);
    assert_eq!(s.tick(80), Action::None);
}
// case A6_running_tick_new_request_during_publish end

// case A7_request_during_publish_then_success_no_publish_before_debounce begin
#[test]
fn case_A7_request_during_publish_then_success_no_publish_before_debounce() {
    let mut s = PublishScheduler::default();
    s.on_request(0);
    s.tick(60);
    s.on_started();
    s.on_request(70);
    s.on_finished(150, true);
    assert_eq!(s.tick(209), Action::None);
    assert_eq!(s.tick(210), Action::Publish);
}
// case A7_request_during_publish_then_success_no_publish_before_debounce end

// case A8_failed_publish_no_retry_before_backoff begin
#[test]
fn case_A8_failed_publish_no_retry_before_backoff() {
    let mut s = PublishScheduler::default();
    s.on_request(0);
    s.tick(60);
    s.on_started();
    s.on_finished(100, false);
    assert_eq!(s.tick(129), Action::None);
}
// case A8_failed_publish_no_retry_before_backoff end



// case config_auto_true_tick_publish begin
#[test]
fn case_config_auto_true_tick_publish() {
    let mut s = PublishScheduler::new(60, true);
    s.on_request(0);
    s.on_request(10);
    s.on_request(20);
    s.on_request(30);
    s.on_request(40);
    assert_eq!(s.tick(100), Action::Publish);
}
// case config_auto_true_tick_publish end

