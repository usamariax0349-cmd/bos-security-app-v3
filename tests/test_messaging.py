"""Guard messaging: the self-serve FAQ browser, ticket submission, and the
reactive keyword-matched auto-reply that both share the same `faqs` table.
"""


def test_guard_can_browse_faqs_without_creating_a_ticket(api, guard_with_password):
    guard_id, email, password = guard_with_password
    status, login = api.call("POST", "/api/guard/login", {"email": email, "password": password})
    guard_token = login["token"]

    status, faqs = api.call("GET", "/api/guard/faqs", token=guard_token)
    assert status == 200
    assert len(faqs) > 0
    for f in faqs:
        assert "question" in f and "answer" in f
        assert "keywords" not in f  # guard sees the Q&A, not the matching internals


def test_ticket_submission_creates_a_message_and_query_status(api, guard_with_password):
    guard_id, email, password = guard_with_password
    status, login = api.call("POST", "/api/guard/login", {"email": email, "password": password})
    guard_token = login["token"]

    status, ticket = api.call(
        "POST", "/api/guard/tickets", {"category": "other", "body": "Testing the ticket flow end to end."},
        token=guard_token,
    )
    assert status == 201, ticket
    assert ticket["ticket_number"]

    status, qstatus = api.call("GET", "/api/guard/query-status", token=guard_token)
    assert status == 200
    assert qstatus["status"] == "open"
    assert qstatus["ticket_number"] == ticket["ticket_number"]


def test_message_matching_a_faq_keyword_gets_an_instant_auto_reply(api, guard_with_password):
    guard_id, email, password = guard_with_password
    status, login = api.call("POST", "/api/guard/login", {"email": email, "password": password})
    guard_token = login["token"]

    # "How do I clock in or out?" is seeded with the keyword "clock in".
    status, sent = api.call(
        "POST", "/api/guard/messages", {"body": "how do I clock in please"}, token=guard_token,
    )
    assert status == 201, sent
    assert sent["auto_replied"] is True

    status, messages = api.call("GET", "/api/guard/messages", token=guard_token)
    assert status == 200
    assert any(m["sender_name"] == "FAQ Auto-Reply" for m in messages)
