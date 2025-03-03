/**
 * Enhanced Setup JavaScript for TA-EDR_Threat_Hunt_Cmd
 * Provides improved UI interactions, validation and feedback
 */
require([
    'jquery',
    'splunkjs/mvc/utils',
    'splunkjs/mvc/tokenutils',
    'splunkjs/mvc/simplexml',
    'underscore',
    'splunkjs/mvc',
    'splunk.util'
], function($, utils, TokenUtils, SimpleXML, _, mvc, splunkUtil) {
    
    // Define the enhanced setup view
    var EnhancedSetupView = {
        // Store references to status elements
        statusElements: {
            main: $('#setup-status')
        },
        
        // Maintain state of credentials
        credentialState: {
            crowdstrike: {},
            sentinelone: {},
            defender: {}
        },

        // Initialize current tenants
        tenants: ['default'],
        
        // Initialize the setup view
        initialize: function() {
            this.createToggleSwitches();
            this.enhanceFormElements();
            this.setupTabs();
            this.bindEvents();
            this.setupValidation();
            this.setupTooltips();
            this.setupCredentialManagement();
            this.loadTenants();
        },
        
        // Create toggle switches for boolean inputs
        createToggleSwitches: function() {
            $('input[type="checkbox"]').each(function() {
                var $checkbox = $(this);
                var $parent = $checkbox.parent();
                
                // Create toggle switch
                var toggleHtml = '<label class="toggle-switch">' +
                    '<input type="checkbox" name="' + $checkbox.attr('name') + '"' + 
                    ($checkbox.prop('checked') ? ' checked' : '') + '>' +
                    '<span class="toggle-slider"></span>' +
                    '</label>';
                
                // Replace checkbox with toggle
                $checkbox.replaceWith(toggleHtml);
            });
        },
        
        // Enhance form elements with better UI/UX
        enhanceFormElements: function() {
            // Add help tooltips to form elements
            $('[data-tooltip]').each(function() {
                var tooltipText = $(this).data('tooltip');
                $(this).after('<span class="tooltip"><span class="tooltip-icon">?</span>' +
                              '<span class="tooltip-text">' + tooltipText + '</span></span>');
            });
            
            // Format credential lists
            this.formatCredentialLists();
        },

        // Set up tabs
        setupTabs: function() {
            var self = this;
            
            // Handle tab navigation
            $('.tab').on('click', function() {
                var tabId = $(this).data('tab');
                
                // Update active tab
                $('.tab').removeClass('active');
                $(this).addClass('active');
                
                // Show selected tab pane
                $('.tab-pane').removeClass('active');
                $('#' + tabId + '-tab').addClass('active');
            });
        },
        
        // Format credential lists into manageable UI
        formatCredentialLists: function() {
            var self = this;
            
            // Process each provider's credential list
            ['crowdstrike', 'sentinelone', 'defender'].forEach(function(provider) {
                var $input = $('#' + provider + '_credentials_list');
                if ($input.length === 0) return;
                
                // Get current credentials
                var credentials = $input.val().split(',').filter(Boolean);
                
                // Create credential container
                var $container = $('#' + provider + '-credentials-container');
                
                // Clear the container
                $container.empty();
                
                // Add credentials to the container
                credentials.forEach(function(cred) {
                    self.addCredentialItem($container, cred, provider);
                });
            });
        },
        
        // Add credential item to container
        addCredentialItem: function($container, credential, provider) {
            var self = this;
            
            // Create credential item
            var $item = $('<div class="credential-item" data-credential="' + credential + '"></div>');
            
            // Parse credential parts (provider_tenant_console)
            var parts = credential.split('_');
            var tenant = parts.length > 1 ? parts[1] : 'default';
            var console = parts.length > 2 ? parts[2] : 'primary';
            
            // Create credential display
            $item.append('<span class="credential-name">' + credential + '</span>');
            
            // Create action buttons
            var $actions = $('<div class="credential-actions"></div>');
            $actions.append('<button type="button" class="btn btn-test test-credential" data-credential="' + credential + '" data-provider="' + provider + '" data-tenant="' + tenant + '" data-console="' + console + '">Test</button>');
            $actions.append('<button type="button" class="btn edit-credential" data-credential="' + credential + '" data-provider="' + provider + '">Edit</button>');
            $actions.append('<button type="button" class="btn remove-credential" data-credential="' + credential + '" data-provider="' + provider + '">Remove</button>');
            
            // Add status indicator
            $actions.append('<span class="credential-status" id="' + credential + '_status"></span>');
            
            $item.append($actions);
            $container.append($item);
            
            // Update internal state
            self.credentialState[provider][credential] = {
                tenant: tenant,
                console: console,
                status: 'unknown'
            };
        },
        
        // Load tenants from tenant list
        loadTenants: function() {
            var $tenantList = $('#tenant_list');
            if ($tenantList.length === 0) return;
            
            var tenantList = $tenantList.val();
            if (tenantList) {
                this.tenants = tenantList.split(',').map(function(t) { return t.trim(); }).filter(Boolean);
                
                // Always ensure default tenant exists
                if (this.tenants.indexOf('default') === -1) {
                    this.tenants.unshift('default');
                }
            } else {
                this.tenants = ['default'];
            }
            
            this.updateTenantInfo();
        },
        
        // Update tenant information display
        updateTenantInfo: function() {
            var self = this;
            var $container = $('#tenant-info-container');
            
            // Clear container
            $container.empty();
            
            // Add tenant information
            this.tenants.forEach(function(tenant) {
                var $tenantInfo = $('<div class="tenant-info" data-tenant="' + tenant + '"></div>');
                
                // Add tenant header
                $tenantInfo.append('<h4>' + tenant.charAt(0).toUpperCase() + tenant.slice(1) + '</h4>');
                
                // Add tenant credentials
                var credentialSummary = self.getTenantCredentials(tenant);
                
                var $credSummary = $('<div class="tenant-credentials"></div>');
                
                if (credentialSummary.total === 0) {
                    $credSummary.append('<p>No credentials configured for this tenant.</p>');
                } else {
                    var providerList = [];
                    for (var provider in credentialSummary.providers) {
                        if (credentialSummary.providers[provider] > 0) {
                            providerList.push(provider + ': ' + credentialSummary.providers[provider]);
                        }
                    }
                    
                    $credSummary.append('<p><strong>Credentials:</strong> ' + providerList.join(', ') + '</p>');
                }
                
                $tenantInfo.append($credSummary);
                $container.append($tenantInfo);
            });
        },
        
        // Get credentials summary for a tenant
        getTenantCredentials: function(tenant) {
            var summary = {
                total: 0,
                providers: {
                    crowdstrike: 0,
                    sentinelone: 0,
                    defender: 0
                }
            };
            
            // Check each provider
            ['crowdstrike', 'sentinelone', 'defender'].forEach(function(provider) {
                // Count credentials for this tenant
                for (var cred in this.credentialState[provider]) {
                    if (this.credentialState[provider][cred].tenant === tenant) {
                        summary.providers[provider]++;
                        summary.total++;
                    }
                }
            }, this);
            
            return summary;
        },
        
        // Bind events to UI elements
        bindEvents: function() {
            var self = this;
            
            // Test connection buttons
            $(document).on('click', '.test-credential', function(e) {
                e.preventDefault();
                var provider = $(this).data('provider');
                var credential = $(this).data('credential');
                var tenant = $(this).data('tenant');
                var console = $(this).data('console');
                
                self.testConnection(provider, credential, tenant, console);
            });
            
            // Test all connections button
            $('#test-all-connections').on('click', function(e) {
                e.preventDefault();
                self.testAllConnections();
            });
            
            // Add credential buttons
            $(document).on('click', '[id^=add-][id$=-credential]', function(e) {
                e.preventDefault();
                var provider = $(this).data('provider');
                self.showAddCredentialModal(provider);
            });
            
            // Remove credential button
            $(document).on('click', '.remove-credential', function(e) {
                e.preventDefault();
                var credential = $(this).data('credential');
                var provider = $(this).data('provider');
                
                self.removeCredential(credential, provider);
            });
            
            // Edit credential button
            $(document).on('click', '.edit-credential', function(e) {
                e.preventDefault();
                var credential = $(this).data('credential');
                var provider = $(this).data('provider');
                
                self.showEditCredentialModal(credential, provider);
            });
            
            // Modal close button
            $('.modal-close, .modal-cancel').on('click', function() {
                $('#credential-modal').hide();
            });
            
            // Close modal when clicking outside
            $(window).on('click', function(e) {
                if ($(e.target).is('.modal')) {
                    $('.modal').hide();
                }
            });
            
            // Save credential button
            $('#save-credential').on('click', function() {
                self.saveCredential();
            });
            
            // Tenant list changes
            $('#tenant_list').on('change', function() {
                self.loadTenants();
            });
            
            // Form submission - add additional validation
            $('#setup-form').on('submit', function(e) {
                if (!self.validateForm()) {
                    e.preventDefault();
                    self.showMessage('error', 'Please fix validation errors before submitting.');
                    return false;
                }
                
                // Show loading message
                self.showMessage('loading', 'Saving configuration...');
                
                return true;
            });
        },
        
        // Setup form validation
        setupValidation: function() {
            var self = this;
            
            // Add validation to number inputs
            $('input[type="number"]').each(function() {
                var $input = $(this);
                var min = $input.attr('min');
                var max = $input.attr('max');
                
                $input.on('change', function() {
                    var value = parseInt($input.val(), 10);
                    
                    if (isNaN(value)) {
                        self.showValidationError($input, 'Please enter a valid number');
                        return;
                    }
                    
                    if (min !== undefined && value < parseInt(min, 10)) {
                        self.showValidationError($input, 'Value must be at least ' + min);
                        return;
                    }
                    
                    if (max !== undefined && value > parseInt(max, 10)) {
                        self.showValidationError($input, 'Value must be at most ' + max);
                        return;
                    }
                    
                    self.clearValidationError($input);
                });
            });
            
            // Add validation to URL inputs
            $('input[name$="_api_url"]').each(function() {
                var $input = $(this);
                
                $input.on('change', function() {
                    var value = $input.val().trim();
                    
                    if (value && !self.isValidUrl(value)) {
                        self.showValidationError($input, 'Please enter a valid URL');
                        return;
                    }
                    
                    self.clearValidationError($input);
                });
            });
            
            // Add validation to email inputs
            $('input[name="alert_email"]').on('change', function() {
                var $input = $(this);
                var value = $input.val().trim();
                
                if (value) {
                    var emails = value.split(',');
                    var invalidEmails = [];
                    
                    emails.forEach(function(email) {
                        if (!self.isValidEmail(email.trim())) {
                            invalidEmails.push(email.trim());
                        }
                    });
                    
                    if (invalidEmails.length > 0) {
                        self.showValidationError($input, 'Invalid email(s): ' + invalidEmails.join(', '));
                        return;
                    }
                }
                
                self.clearValidationError($input);
            });
            
            // Validate tenant list
            $('#tenant_list').on('change', function() {
                var $input = $(this);
                var value = $input.val().trim();
                
                if (value) {
                    var tenants = value.split(',');
                    var invalidTenants = [];
                    
                    tenants.forEach(function(tenant) {
                        if (!self.isValidIdentifier(tenant.trim())) {
                            invalidTenants.push(tenant.trim());
                        }
                    });
                    
                    if (invalidTenants.length > 0) {
                        self.showValidationError($input, 'Invalid tenant ID(s): ' + invalidTenants.join(', ') + '. Use only alphanumeric characters, underscores, and hyphens.');
                        return;
                    }
                }
                
                self.clearValidationError($input);
            });
        },
        
        // Setup tooltips
        setupTooltips: function() {
            // No additional setup needed as tooltips are created in enhanceFormElements
        },
        
        // Setup credential management
        setupCredentialManagement: function() {
            // No additional setup needed as modal is already in HTML
        },
        
        // Show modal for adding a new credential
        showAddCredentialModal: function(provider) {
            // Reset form
            $('#credential-form')[0].reset();
            
            // Set provider
            $('#credential-provider').val(provider);
            $('#credential-original').val('');
            
            // Set modal title
            $('.modal-title').text('Add ' + provider.charAt(0).toUpperCase() + provider.slice(1) + ' Credential');
            
            // Hide any previous errors
            $('#credential-modal-error').hide();
            
            // Show modal
            $('#credential-modal').show();
        },
        
        // Show modal for editing a credential
        showEditCredentialModal: function(credential, provider) {
            // Reset form
            $('#credential-form')[0].reset();
            
            // Parse credential parts
            var parts = credential.split('_');
            var tenant = parts.length > 1 ? parts[1] : 'default';
            var console = parts.length > 2 ? parts[2] : 'primary';
            
            // Set form values
            $('#credential-provider').val(provider);
            $('#credential-original').val(credential);
            $('#credential-tenant').val(tenant);
            $('#credential-console').val(console);
            
            // Try to get existing username from Splunk
            // Note: We can't pre-fill password for security reasons
            
            // Set modal title
            $('.modal-title').text('Edit ' + provider.charAt(0).toUpperCase() + provider.slice(1) + ' Credential');
            
            // Hide any previous errors
            $('#credential-modal-error').hide();
            
            // Show modal
            $('#credential-modal').show();
        },
        
        // Save credential
        saveCredential: function() {
            var provider = $('#credential-provider').val();
            var originalCredential = $('#credential-original').val();
            var tenant = $('#credential-tenant').val() || 'default';
            var console = $('#credential-console').val() || 'primary';
            var username = $('#credential-username').val();
            var password = $('#credential-password').val();
            
            // Validate inputs
            if (!username) {
                this.showModalError('Username / Client ID is required');
                return;
            }
            
            if (!password && !originalCredential) {
                this.showModalError('Password / Client Secret is required for new credentials');
                return;
            }
            
            // Validate tenant and console format (only alphanumeric, underscores, and hyphens)
            if (!this.isValidIdentifier(tenant)) {
                this.showModalError('Tenant can only contain alphanumeric characters, underscores, and hyphens');
                return;
            }
            
            if (!this.isValidIdentifier(console)) {
                this.showModalError('Console can only contain alphanumeric characters, underscores, and hyphens');
                return;
            }
            
            // Create credential name
            var newCredential = provider + '_' + tenant + '_' + console;
            
            // Handle updating vs adding
            if (originalCredential) {
                if (originalCredential !== newCredential) {
                    // Name changed, remove the old one
                    this.removeCredential(originalCredential, provider, false);
                }
            }
            
            // Save credential to Splunk
            this.saveCredentialToSplunk(newCredential, username, password, function(success) {
                if (success) {
                    // Update UI
                    var $container = $('#' + provider + '-credentials-container');
                    
                    // Check if credential already exists
                    if ($container.find('[data-credential="' + newCredential + '"]').length > 0) {
                        // Update status
                        $('#' + newCredential + '_status').removeClass('verified unverified error').text('');
                    } else {
                        // Add new credential to UI
                        this.addCredentialItem($container, newCredential, provider);
                    }
                    
                    // Update hidden input with all credentials
                    this.updateCredentialList(provider);
                    
                    // Add tenant to tenant list if it doesn't exist
                    if (this.tenants.indexOf(tenant) === -1) {
                        this.tenants.push(tenant);
                        $('#tenant_list').val(this.tenants.join(','));
                        this.updateTenantInfo();
                    }
                    
                    // Close modal
                    $('#credential-modal').hide();
                    
                    // Show success message
                    this.showMessage('success', 'Credential saved successfully.');
                }
            }.bind(this));
        },
        
        // Remove credential
        removeCredential: function(credential, provider, updateUI = true) {
            // Remove from state
            if (this.credentialState[provider] && this.credentialState[provider][credential]) {
                delete this.credentialState[provider][credential];
            }
            
            if (updateUI) {
                // Remove from UI
                $('[data-credential="' + credential + '"]').remove();
                
                // Update hidden input
                this.updateCredentialList(provider);
                
                // Update tenant info
                this.updateTenantInfo();
                
                // Show success message
                this.showMessage('success', 'Credential removed successfully.');
            }
        },
        
        // Update credential list in hidden input
        updateCredentialList: function(provider) {
            var credentials = Object.keys(this.credentialState[provider] || {});
            $('#' + provider + '_credentials_list').val(credentials.join(','));
        },
        
        // Save credential to Splunk
        saveCredentialToSplunk: function(credential, username, password, callback) {
            // For the setup page, we don't actually save the credential directly to Splunk
            // Instead, we just update our UI state and the hidden input field
            // The actual credential saving happens when the form is submitted to the server
            
            // Split credential into parts
            var parts = credential.split('_');
            var provider = parts[0];
            var tenant = parts.length > 1 ? parts[1] : 'default';
            var console = parts.length > 2 ? parts[2] : 'primary';
            
            // Update state
            if (!this.credentialState[provider]) {
                this.credentialState[provider] = {};
            }
            
            this.credentialState[provider][credential] = {
                tenant: tenant,
                console: console,
                status: 'unknown'
            };
            
            // Update credential list
            this.updateCredentialList(provider);
            
            // Call callback
            if (callback) {
                callback(true);
            }
        },
        
        // Show modal error
        showModalError: function(message) {
            var $errorEl = $('#credential-modal-error');
            
            // Set error message
            $errorEl.text(message).show();
        },
        
        // Hide modal error
        hideModalError: function() {
            $('#credential-modal-error').hide();
        },
        
        // Test connection for a specific provider
        testConnection: function(provider, credential, tenant, console) {
            var self = this;
            var $status = $('#' + credential + '_status');
            
            // Show testing status
            $status.removeClass('verified unverified error').addClass('loading').text('Testing...');
            
            // Create the data to send
            var url = splunkUtil.make_url('/splunkd/__raw/services/TA-EDR_Threat_Hunt_Cmd/setup_handler/_execute');
            var data = {
                provider: provider,
                tenant: tenant,
                console: console
            };
            
            // Make the request
            $.ajax({
                url: url,
                type: 'POST',
                data: data,
                dataType: 'json',
                success: function(response) {
                    try {
                        var result = JSON.parse(response.entry[0].content.test_result);
                        
                        if (result.success) {
                            $status.removeClass('loading').addClass('verified').html('✓ Verified');
                            
                            // Update state
                            if (self.credentialState[provider] && self.credentialState[provider][credential]) {
                                self.credentialState[provider][credential].status = 'verified';
                            }
                        } else {
                            $status.removeClass('loading').addClass('unverified').html('✗ Failed');
                            
                            // Show error details
                            self.showConnectionError(credential, result.message);
                            
                            // Update state
                            if (self.credentialState[provider] && self.credentialState[provider][credential]) {
                                self.credentialState[provider][credential].status = 'failed';
                            }
                        }
                    } catch (e) {
                        $status.removeClass('loading').addClass('error').html('✗ Error');
                    self.showConnectionError(credential, 'Request failed: ' + error);
                    
                    // Update state
                    if (self.credentialState[provider] && self.credentialState[provider][credential]) {
                        self.credentialState[provider][credential].status = 'error';
                    }
                }
            });
        },
        
        // Test all connections
        testAllConnections: function() {
            var self = this;
            var providers = ['crowdstrike', 'sentinelone', 'defender'];
            var totalCredentials = 0;
            var testedCredentials = 0;
            var successfulCredentials = 0;
            
            // Count total credentials
            providers.forEach(function(provider) {
                totalCredentials += Object.keys(self.credentialState[provider]).length;
            });
            
            if (totalCredentials === 0) {
                self.showMessage('warning', 'No credentials to test. Please add credentials first.');
                return;
            }
            
            // Show testing message
            self.showMessage('loading', 'Testing ' + totalCredentials + ' credentials...');
            
            // Test each credential
            providers.forEach(function(provider) {
                for (var credential in self.credentialState[provider]) {
                    (function(cred, prov) {
                        var tenant = self.credentialState[prov][cred].tenant;
                        var console = self.credentialState[prov][cred].console;
                        
                        var $status = $('#' + cred + '_status');
                        $status.removeClass('verified unverified error').addClass('loading').text('Testing...');
                        
                        // Create the data to send
                        var url = splunkUtil.make_url('/splunkd/__raw/services/TA-EDR_Threat_Hunt_Cmd/setup_handler/_execute');
                        var data = {
                            provider: prov,
                            tenant: tenant,
                            console: console
                        };
                        
                        // Make the request
                        $.ajax({
                            url: url,
                            type: 'POST',
                            data: data,
                            dataType: 'json',
                            success: function(response) {
                                testedCredentials++;
                                
                                try {
                                    var result = JSON.parse(response.entry[0].content.test_result);
                                    
                                    if (result.success) {
                                        $status.removeClass('loading').addClass('verified').html('✓ Verified');
                                        successfulCredentials++;
                                        
                                        // Update state
                                        if (self.credentialState[prov] && self.credentialState[prov][cred]) {
                                            self.credentialState[prov][cred].status = 'verified';
                                        }
                                    } else {
                                        $status.removeClass('loading').addClass('unverified').html('✗ Failed');
                                        
                                        // Update state
                                        if (self.credentialState[prov] && self.credentialState[prov][cred]) {
                                            self.credentialState[prov][cred].status = 'failed';
                                        }
                                    }
                                } catch (e) {
                                    $status.removeClass('loading').addClass('error').html('✗ Error');
                                    
                                    // Update state
                                    if (self.credentialState[prov] && self.credentialState[prov][cred]) {
                                        self.credentialState[prov][cred].status = 'error';
                                    }
                                }
                                
                                // If all tests are complete, show summary
                                if (testedCredentials === totalCredentials) {
                                    if (successfulCredentials === totalCredentials) {
                                        self.showMessage('success', 'All ' + totalCredentials + ' credentials verified successfully.');
                                    } else {
                                        self.showMessage('warning', 'Completed testing ' + totalCredentials + ' credentials. ' + successfulCredentials + ' successful, ' + (totalCredentials - successfulCredentials) + ' failed.');
                                    }
                                }
                            },
                            error: function(xhr, status, error) {
                                testedCredentials++;
                                
                                $status.removeClass('loading').addClass('error').html('✗ Error');
                                
                                // Update state
                                if (self.credentialState[prov] && self.credentialState[prov][cred]) {
                                    self.credentialState[prov][cred].status = 'error';
                                }
                                
                                // If all tests are complete, show summary
                                if (testedCredentials === totalCredentials) {
                                    self.showMessage('warning', 'Completed testing ' + totalCredentials + ' credentials. ' + successfulCredentials + ' successful, ' + (totalCredentials - successfulCredentials) + ' failed.');
                                }
                            }
                        });
                    })(credential, provider);
                }
            });
        },
        
        // Show connection error
        showConnectionError: function(credential, message) {
            // Create error popup
            var $popup = $('<div class="connection-error-popup">' +
                          '<div class="error-header">Connection Error</div>' +
                          '<div class="error-message">' + message + '</div>' +
                          '<button class="btn btn-small close-error">Close</button>' +
                          '</div>');
            
            // Add to credential item
            $('[data-credential="' + credential + '"]').append($popup);
            
            // Add close handler
            $popup.find('.close-error').on('click', function() {
                $popup.remove();
            });
            
            // Auto-close after 10 seconds
            setTimeout(function() {
                $popup.fadeOut(500, function() {
                    $popup.remove();
                });
            }, 10000);
        },
        
        // Show validation error
        showValidationError: function($input, message) {
            // Remove any existing error
            this.clearValidationError($input);
            
            // Create error message
            var $error = $('<div class="validation-error">' + message + '</div>');
            
            // Add error class to input
            $input.addClass('input-error');
            
            // Add error message after input
            $input.after($error);
        },
        
        // Clear validation error
        clearValidationError: function($input) {
            // Remove error class
            $input.removeClass('input-error');
            
            // Remove error message
            $input.siblings('.validation-error').remove();
        },
        
        // Show status message
        showMessage: function(type, message) {
            var self = this;
            var $status = this.statusElements.main;
            
            // Clear existing messages
            $status.removeClass('success error warning loading').empty();
            
            // Add new message
            $status.addClass(type).text(message);
            
            // Auto-clear success messages after 5 seconds
            if (type === 'success') {
                setTimeout(function() {
                    $status.fadeOut(500, function() {
                        $status.removeClass('success').empty().show();
                    });
                }, 5000);
            }
        },
        
        // Validate the entire form
        validateForm: function() {
            var isValid = true;
            
            // Validate number inputs
            $('input[type="number"]').each(function() {
                var $input = $(this);
                var value = parseInt($input.val(), 10);
                var min = parseInt($input.attr('min'), 10);
                var max = parseInt($input.attr('max'), 10);
                
                if (isNaN(value)) {
                    isValid = false;
                    return;
                }
                
                if (!isNaN(min) && value < min) {
                    isValid = false;
                    return;
                }
                
                if (!isNaN(max) && value > max) {
                    isValid = false;
                    return;
                }
            });
            
            // Validate URL inputs
            $('input[name$="_api_url"]').each(function() {
                var $input = $(this);
                var value = $input.val().trim();
                
                if (value && !EnhancedSetupView.isValidUrl(value)) {
                    isValid = false;
                    return;
                }
            });
            
            // Validate email inputs
            $('input[name="alert_email"]').each(function() {
                var $input = $(this);
                var value = $input.val().trim();
                
                if (value) {
                    var emails = value.split(',');
                    var allValid = true;
                    
                    emails.forEach(function(email) {
                        if (!EnhancedSetupView.isValidEmail(email.trim())) {
                            allValid = false;
                        }
                    });
                    
                    if (!allValid) {
                        isValid = false;
                        return;
                    }
                }
            });
            
            return isValid;
        },
        
        // Check if a string is a valid URL
        isValidUrl: function(url) {
            try {
                new URL(url);
                return true;
            } catch (e) {
                return false;
            }
        },
        
        // Check if a string is a valid email
        isValidEmail: function(email) {
            var re = /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
            return re.test(String(email).toLowerCase());
        },
        
        // Check if a string is a valid identifier
        isValidIdentifier: function(id) {
            var re = /^[a-zA-Z0-9_-]+$/;
            return re.test(String(id));
        }
    };
    
    // Initialize the enhanced setup view
    $(document).ready(function() {
        EnhancedSetupView.initialize();
    });
});✗ Error');
                        self.showConnectionError(credential, 'Invalid response format: ' + e.message);
                    }
                },
                error: function(xhr, status, error) {
                    $status.removeClass('loading').addClass('error').html('