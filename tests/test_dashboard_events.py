"""Tests for the EventBus class."""

from dashboard.events import EventBus


def test_subscribe_and_publish():
    """Test that subscribers receive published events."""
    bus = EventBus()
    received = []
    bus.subscribe("test", lambda data: received.append(data))
    bus.publish("test", {"key": "value"})
    assert len(received) == 1
    assert received[0] == {"key": "value"}


def test_multiple_subscribers():
    """Test that multiple subscribers all receive events."""
    bus = EventBus()
    received_a = []
    received_b = []
    bus.subscribe("test", lambda data: received_a.append(data))
    bus.subscribe("test", lambda data: received_b.append(data))
    bus.publish("test", "hello")
    assert received_a == ["hello"]
    assert received_b == ["hello"]


def test_unsubscribe():
    """Test that unsubscribed listeners no longer receive events."""
    bus = EventBus()
    received = []

    def callback(data):
        received.append(data)

    bus.subscribe("test", callback)
    bus.publish("test", "first")
    assert len(received) == 1

    bus.unsubscribe("test", callback)
    bus.publish("test", "second")
    assert len(received) == 1


def test_clear_specific_event():
    """Test clearing listeners for a specific event type."""
    bus = EventBus()
    received = []
    bus.subscribe("test", lambda data: received.append(data))
    bus.subscribe("other", lambda data: None)
    bus.clear("test")
    bus.publish("test", "should not receive")
    assert len(received) == 0


def test_clear_all():
    """Test clearing all listeners."""
    bus = EventBus()
    bus.subscribe("a", lambda data: None)
    bus.subscribe("b", lambda data: None)
    bus.clear()
    bus.publish("a", "ignored")
    bus.publish("b", "ignored")


def test_bad_subscriber_doesnt_break_bus():
    """Test that a subscriber that throws doesn't break the bus."""
    bus = EventBus()
    received = []

    def bad_callback(data):
        raise ValueError("oops")

    def good_callback(data):
        received.append(data)

    bus.subscribe("test", bad_callback)
    bus.subscribe("test", good_callback)
    bus.publish("test", "hello")
    assert received == ["hello"]


def test_publish_to_empty_event_type():
    """Test publishing to an event type with no subscribers."""
    bus = EventBus()
    bus.publish("nonexistent", "data")  # Should not raise


def test_event_bus_isolation():
    """Test that different event types are isolated."""
    bus = EventBus()
    received_a = []
    received_b = []
    bus.subscribe("a", lambda data: received_a.append(data))
    bus.subscribe("b", lambda data: received_b.append(data))
    bus.publish("a", "for_a")
    bus.publish("b", "for_b")
    assert received_a == ["for_a"]
    assert received_b == ["for_b"]
