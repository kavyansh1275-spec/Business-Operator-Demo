from demo_server import page
from business_operator import seed_demo, dashboard_data

seed_demo()
html = page()
assert 'Business Operator' in html
assert 'DEMO · SAMPLE DATA' in html
assert 'Payment shortfall' in html
assert 'Conflicting amounts' in html
b, recs, findings, actions = dashboard_data('demo')
assert len(recs) >= 5
assert any(f['kind'] == 'payment_mismatch' for f in findings)
assert any(f['kind'] == 'conflict' for f in findings)
print('DEMO TESTS PASSED')
