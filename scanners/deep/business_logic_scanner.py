# scanners/deep/business_logic_scanner.py - UPDATED VERSION

from urllib.parse import urljoin
from ..base_scanner import SecurityScanner

class BusinessLogicScanner(SecurityScanner):
    """Specialized business logic vulnerability scanner with price manipulation testing"""
    
    def run_scan(self):
        """Run business logic security scan"""
        try:
            print(f"[*] Starting business logic scan for: {self.target_url}")
            self.update_progress(10, "💼 Starting business logic scan...")
            
            if self.check_stop_flag():
                return self._build_results('stopped')
            
            # Test business logic
            self.update_progress(50, "🔍 Testing business logic vulnerabilities...")
            self.test_business_logic()
            
            if self.check_stop_flag():
                return self._build_results('stopped')
            
            # Finalize
            self.update_progress(95, "📊 Generating business logic report...")
            security_score = self.calculate_security_score()
            
            self.update_progress(100, "✅ Business logic scan completed!")
            
            return self._build_results('completed', security_score)
            
        except Exception as e:
            print(f"[-] Business logic scan error: {e}")
            return self._build_results('error', error_message=str(e))

    def test_business_logic(self):
        """Test for business logic vulnerabilities including price manipulation"""
        try:
            # Test for IDOR (Insecure Direct Object Reference)
            test_paths = [
                '/user/1', '/admin/1', '/profile/1', '/order/1', 
                '/account/1', '/invoice/1', '/document/1'
            ]
            
            for path in test_paths:
                if self.check_stop_flag(): 
                    return
                
                test_url = urljoin(self.target_url, path)
                success, response = self.safe_request('GET', test_url)
                
                if success and response.status_code == 200:
                    # Check if we can access other users' data
                    self.vulnerabilities.append({
                        'category': 'Business Logic',
                        'risk_level': 'High',
                        'title': 'Potential Insecure Direct Object Reference (IDOR)',
                        'description': f'Accessible resource without proper authorization: {path}',
                        'location': test_url,
                        'evidence': f'Resource {path} accessible without access control',
                        'recommendation': 'Implement proper authorization checks for all object references'
                    })

            # NEW: Test for price manipulation vulnerabilities
            self.test_price_manipulation()
            
            # NEW: Test for quantity manipulation
            self.test_quantity_manipulation()
            
            # NEW: Test for coupon/ discount abuse
            self.test_discount_abuse()

            # Test for workflow bypass
            workflow_endpoints = ['/checkout/confirm', '/payment/process', '/admin/delete']
            for endpoint in workflow_endpoints:
                test_url = urljoin(self.target_url, endpoint)
                success, response = self.safe_request('POST', test_url, data={'test': 'bypass'})
                
                if success and response.status_code == 200:
                    self.vulnerabilities.append({
                        'category': 'Business Logic',
                        'risk_level': 'Medium',
                        'title': 'Potential Workflow Bypass',
                        'description': f'Endpoint {endpoint} might be accessible without proper workflow validation',
                        'location': test_url,
                        'evidence': 'Endpoint responded to direct access',
                        'recommendation': 'Implement proper workflow state validation'
                    })
                    
        except Exception as e:
            print(f"[-] Business logic test error: {e}")

    def test_price_manipulation(self):
        """NEW: Test for price manipulation vulnerabilities"""
        try:
            forms = self.extract_forms()
            
            for form in forms:
                if self.check_stop_flag():
                    return
                    
                # Find price-related fields
                price_fields = [
                    field for field in form['inputs'] 
                    if any(keyword in field['name'].lower() for keyword in 
                          ['price', 'amount', 'cost', 'total', 'value', 'fee'])
                ]
                
                for price_field in price_fields:
                    # Test negative prices
                    test_data = self._create_form_data(form, {price_field['name']: '-1.00'})
                    success, response = self._submit_form_with_data(form, test_data)
                    
                    if success and response.status_code in [200, 201]:
                        self.vulnerabilities.append({
                            'category': 'Business Logic',
                            'risk_level': 'High',
                            'title': 'Negative Price Manipulation',
                            'description': f'Form accepts negative price for field: {price_field["name"]}',
                            'location': self._get_form_url(form),
                            'evidence': f'Negative price accepted: -1.00',
                            'recommendation': 'Validate price ranges server-side and reject negative values'
                        })
                    
                    # Test zero prices
                    test_data = self._create_form_data(form, {price_field['name']: '0.00'})
                    success, response = self._submit_form_with_data(form, test_data)
                    
                    if success and response.status_code in [200, 201]:
                        self.vulnerabilities.append({
                            'category': 'Business Logic',
                            'risk_level': 'Medium',
                            'title': 'Zero Price Manipulation',
                            'description': f'Form accepts zero price for field: {price_field["name"]}',
                            'location': self._get_form_url(form),
                            'evidence': f'Zero price accepted: 0.00',
                            'recommendation': 'Validate minimum price thresholds server-side'
                        })
                    
                    # Test extremely large prices (potential integer overflow)
                    test_data = self._create_form_data(form, {price_field['name']: '9999999999.99'})
                    success, response = self._submit_form_with_data(form, test_data)
                    
                    if success and response.status_code in [200, 201]:
                        self.vulnerabilities.append({
                            'category': 'Business Logic',
                            'risk_level': 'Medium',
                            'title': 'Large Price Value Accepted',
                            'description': f'Form accepts extremely large price for field: {price_field["name"]}',
                            'location': self._get_form_url(form),
                            'evidence': f'Large price accepted: 9999999999.99',
                            'recommendation': 'Implement reasonable price limits and input validation'
                        })
                    
                    # Test price override with hidden fields
                    hidden_fields = [f for f in form['inputs'] if f['type'] == 'hidden']
                    for hidden_field in hidden_fields:
                        if any(keyword in hidden_field['name'].lower() for keyword in ['price', 'amount']):
                            test_data = self._create_form_data(form, {hidden_field['name']: '0.01'})
                            success, response = self._submit_form_with_data(form, test_data)
                            
                            if success and response.status_code in [200, 201]:
                                self.vulnerabilities.append({
                                    'category': 'Business Logic',
                                    'risk_level': 'High',
                                    'title': 'Hidden Price Field Manipulation',
                                    'description': f'Hidden price field can be manipulated: {hidden_field["name"]}',
                                    'location': self._get_form_url(form),
                                    'evidence': f'Hidden field {hidden_field["name"]} accepted modified value',
                                    'recommendation': 'Never trust client-side values for pricing; validate server-side'
                                })
                                
        except Exception as e:
            print(f"[-] Price manipulation test error: {e}")

    def test_quantity_manipulation(self):
        """NEW: Test for quantity manipulation vulnerabilities"""
        try:
            forms = self.extract_forms()
            
            for form in forms:
                if self.check_stop_flag():
                    return
                    
                # Find quantity-related fields
                quantity_fields = [
                    field for field in form['inputs'] 
                    if any(keyword in field['name'].lower() for keyword in 
                          ['quantity', 'qty', 'amount', 'number', 'count'])
                ]
                
                for quantity_field in quantity_fields:
                    # Test negative quantities
                    test_data = self._create_form_data(form, {quantity_field['name']: '-1'})
                    success, response = self._submit_form_with_data(form, test_data)
                    
                    if success and response.status_code in [200, 201]:
                        self.vulnerabilities.append({
                            'category': 'Business Logic',
                            'risk_level': 'High',
                            'title': 'Negative Quantity Manipulation',
                            'description': f'Form accepts negative quantity for field: {quantity_field["name"]}',
                            'location': self._get_form_url(form),
                            'evidence': f'Negative quantity accepted: -1',
                            'recommendation': 'Validate quantity ranges server-side and reject negative values'
                        })
                    
                    # Test zero quantities
                    test_data = self._create_form_data(form, {quantity_field['name']: '0'})
                    success, response = self._submit_form_with_data(form, test_data)
                    
                    if success and response.status_code in [200, 201]:
                        self.vulnerabilities.append({
                            'category': 'Business Logic',
                            'risk_level': 'Low',
                            'title': 'Zero Quantity Accepted',
                            'description': f'Form accepts zero quantity for field: {quantity_field["name"]}',
                            'location': self._get_form_url(form),
                            'evidence': f'Zero quantity accepted: 0',
                            'recommendation': 'Validate minimum quantity thresholds server-side'
                        })
                    
                    # Test extremely large quantities
                    test_data = self._create_form_data(form, {quantity_field['name']: '999999'})
                    success, response = self._submit_form_with_data(form, test_data)
                    
                    if success and response.status_code in [200, 201]:
                        self.vulnerabilities.append({
                            'category': 'Business Logic',
                            'risk_level': 'Medium',
                            'title': 'Large Quantity Accepted',
                            'description': f'Form accepts extremely large quantity for field: {quantity_field["name"]}',
                            'location': self._get_form_url(form),
                            'evidence': f'Large quantity accepted: 999999',
                            'recommendation': 'Implement reasonable quantity limits to prevent inventory issues'
                        })
                                
        except Exception as e:
            print(f"[-] Quantity manipulation test error: {e}")

    def test_discount_abuse(self):
        """NEW: Test for discount/coupon abuse vulnerabilities"""
        try:
            forms = self.extract_forms()
            
            for form in forms:
                if self.check_stop_flag():
                    return
                    
                # Find discount/coupon fields
                discount_fields = [
                    field for field in form['inputs'] 
                    if any(keyword in field['name'].lower() for keyword in 
                          ['discount', 'coupon', 'promo', 'voucher', 'code'])
                ]
                
                for discount_field in discount_fields:
                    # Test common discount bypass patterns
                    test_codes = [
                        '100PERCENT', 'FREE', '0', 'NULL', 'ADMIN',
                        'TEST', 'DEBUG', 'BYPASS', 'HACK', 'OFF'
                    ]
                    
                    for test_code in test_codes:
                        test_data = self._create_form_data(form, {discount_field['name']: test_code})
                        success, response = self._submit_form_with_data(form, test_data)
                        
                        if success and response.status_code in [200, 201]:
                            # Check if order total was reduced
                            if any(indicator in response.text.lower() for indicator in ['success', 'applied', 'discount']):
                                self.vulnerabilities.append({
                                    'category': 'Business Logic',
                                    'risk_level': 'Medium',
                                    'title': 'Potential Discount Code Bypass',
                                    'description': f'Discount code field accepted test value: {test_code}',
                                    'location': self._get_form_url(form),
                                    'evidence': f'Discount code {test_code} was accepted',
                                    'recommendation': 'Implement proper coupon code validation and rate limiting'
                                })
                                break
                                
        except Exception as e:
            print(f"[-] Discount abuse test error: {e}")

    def _create_form_data(self, form, overrides):
        """Create form data with overrides for specific fields"""
        data = {}
        for input_field in form['inputs']:
            if input_field['name'] in overrides:
                data[input_field['name']] = overrides[input_field['name']]
            else:
                data[input_field['name']] = input_field.get('value', '')
        return data

    def _submit_form_with_data(self, form, data):
        """Submit form with custom data"""
        form_url = self._get_form_url(form)
        form_method = form.get('method', 'get').lower()
        
        if form_method == 'post':
            return self.safe_request('POST', form_url, data=data)
        else:
            return self.safe_request('GET', form_url, params=data)

    def _get_form_url(self, form):
        """Get full URL for form action"""
        form_action = form.get('action', '')
        return urljoin(self.target_url, form_action)