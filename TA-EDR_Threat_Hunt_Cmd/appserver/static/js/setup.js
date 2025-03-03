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
            crowdstrike: $('#crowdstrike_status'),
            sentinelone: $('#sentinelone_status'),
            defender: $('#defender_status')
        },
        
        // Maintain state of credentials
        credentialState: {
            crowdstrike: {},
            sentinelone: {},
            defender: {}
        },
        
        // Initialize the setup view
        initialize: function() {
            this.createToggleSwitches();
            this.enhanceFormElements();
            this.bindEvents();
            this.setupValidation();
            this.setupTooltips();
            this.setupCredentialManagement();
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
                var $container = $('<div class="credentials-container" id="' + provider + '_credentials_container"></div>');
                $input.after($container);
                
                // Hide the original input
                $input.hide();
                
                // Add credentials to the container
                credentials.forEach(function(cred) {
                    self.addCredentialItem($container, cred, provider);
                });
                
                // Add "Add Credential" button
                var $addButton = $('<button type="button" class="btn btn-primary add-credential" data-provider="' + provider + '">' +
                                  'Add ' + provider.charAt(0).toUpperCase() + provider.slice(1) + ' Credential</button>');
                $container.after($addButton);
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
            $actions.append('<button type="button" class="btn edit-credential" data-credential="' + credential + '">Edit</button>');
            $actions.append('<button type="button" class="btn remove-credential" data-credential="' + credential + '">Remove</button>');
            
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
        
        // Bind events to UI elements
        bindEvents: function() {
            var self = this;
            
            // Test connection buttons for each provider
            $(document).on('click', '.test-credential', function(e) {
                e.preventDefault();
                var provider = $(this).data('provider');
                var credential = $(this).data('credential');
                var tenant = $(this).data('tenant');
                var console = $(this).data('console');
                
                self.testConnection(provider, credential, tenant, console);
            });
            
            // Add credential button
            $(document).on('click', '.add-credential', function(e) {
                e.preventDefault();
                var provider = $(this).data('provider');
                self.showAddCredentialModal(provider);
            });
            
            // Remove credential button
            $(document).on('click', '.remove-credential', function(e) {
                e.preventDefault();
                var credential = $(this).data('credential');
                var provider = credential.split('_')[0];
                
                self.removeCredential(credential, provider);
            });
            
            // Edit credential button
            $(document).on('click', '.edit-credential', function(e) {
                e.preventDefault();
                var credential = $(this).data('credential');
                var provider = credential.split('_')[0];
                
                self.showEditCredentialModal(credential, provider);
            });
            
            // Form submission - add additional validation
            $('form').on('submit', function(e) {
                if (!self.validateForm()) {
                    e.preventDefault();
                    return false;
                }
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
            $('input[type="url"]').each(function() {
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
            $('input[type="email"]').each(function() {
                var $input = $(this);
                
                $input.on('change', function() {
                    var value = $input.val().trim();
                    
                    if (value && !self.isValidEmail(value)) {
                        self.showValidationError($input, 'Please enter a valid email address');
                        return;
                    }
                    
                    self.clearValidationError($input);
                });
            });
        },
        
        // Setup tooltips
        setupTooltips: function() {
            // No additional setup needed as tooltips are created in enhanceFormElements
        },
        
        // Setup credential management
        setupCredentialManagement: function() {
            // Create modal for adding/editing credentials
            this.createCredentialModal();
        },
        
        // Create modal for credential management
        createCredentialModal: function() {
            // Create modal if it doesn't exist
            if ($('#credential-modal').length === 0) {
                var modalHtml = 
                    '<div id="credential-modal" class="modal fade" tabindex="-1" role="dialog">' +
                    '  <div class="modal-dialog" role="document">' +
                    '    <div class="modal-content">' +
                    '      <div class="modal-header">' +
                    '        <h4 class="modal-title">Manage Credential</h4>' +
                    '        <button type="button" class="close" data-dismiss="modal" aria-label="Close">' +
                    '          <span aria-hidden="true">&times;</span>' +
                    '        </button>' +
                    '      </div>' +
                    '      <div class="modal-body">' +
                    '        <form id="credential-form">' +
                    '          <input type="hidden" id="credential-provider">' +
                    '          <input type="hidden" id="credential-original">' +
                    '          <div class="form-group">' +
                    '            <label for="credential-tenant">Tenant</label>' +
                    '            <input type="text" class="form-control" id="credential-tenant" placeholder="default">' +
                    '          </div>' +
                    '          <div class="form-group">' +
                    '            <label for="credential-console">Console</label>' +
                    '            <input type="text" class="form-control" id="credential-console" placeholder="primary">' +
                    '          </div>' +
                    '          <div class="form-group">' +
                    '            <label for="credential-username">Username / Client ID</label>' +
                    '            <input type="text" class="form-control" id="credential-username">' +
                    '          </div>' +
                    '          <div class="form-group">' +
                    '            <label for="credential-password">Password / Client Secret</label>' +
                    '            <input type="password" class="form-control" id="credential-password">' +
                    '          </div>' +
                    '        </form>' +
                    '      </div>' +
                    '      <div class="modal-footer">' +
                    '        <button type="button" class="btn btn-secondary" data-dismiss="modal">Cancel</button>' +
                    '        <button type="button" class="btn btn-primary" id="save-credential">Save</button>' +
                    '      </div>' +
                    '    </div>' +
                    '  </div>' +
                    '</div>';
                
                // Append modal to the body
                $('body').append(modalHtml);
                
                // Bind save event
                var self = this;
                $('#save-credential').on('click', function() {
                    self.saveCredential();
                });
            }
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
            
            // Show modal
            $('#credential-modal').modal('show');
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
            
            // Show modal
            $('#credential-modal').modal('show');
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
                    var $container = $('#' + provider + '_credentials_container');
                    
                    // Check if credential already exists
                    if ($container.find('[data-credential="' + newCredential + '"]').length > 0) {
                        // Update status
                        $('#' + newCredential + '_status').removeClass('verified unverified').text('');
                    } else {
                        // Add new credential to UI
                        this.addCredentialItem($container, newCredential, provider);
                    }
                    
                    // Update hidden input with all credentials
                    this.updateCredentialList(provider);
                    
                    // Close modal
                    $('#credential-modal').modal('hide');
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
            
            // Call callback
            if (callback) {
                callback(true);
            }
        },
        
        // Show modal error
        showModalError: function(message) {
            // Check if error message element exists
            var $errorEl = $('#credential-modal-error');
            if ($errorEl.length === 0) {
                // Create error element
                $errorEl = $('<div id="credential-modal-error" class="error"></div>');
                $('#credential-form').prepend($errorEl);
            }
            
            // Set error message
            $errorEl.text(message);
        },
        
        // Hide modal error
        hideModalError: function() {
            $('#credential-modal-error').remove();
        },
        
        // Test connection for a specific provider
        testConnection: function(provider, credential, tenant, console) {
            var self = this;
            var $status = $('#' + credential + '_status');
            
            // Show testing status
            $status.removeClass('verified unverified').addClass('loading').text('Testing...');
            
            // Create the data to send
            var url = splunkUtil.make_url('/splunkd/__raw/services/TA-EDR_Threat_Hunt_Cmd/test/_execute');
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
                        $status.removeClass('loading').addClass('unverified').html('✗ Error');
                        self.showConnectionError(credential, 'Invalid response format: ' + e.message);
                    }
                },
                error: function(xhr, status, error) {
                    $status.removeClass('loading').addClass('unverified').html('✗ Error');
                    self.showConnectionError(credential, 'Request failed: ' + error);
                    
                    // Update state
                    if (self.credentialState[provider] && self.credentialState[provider][credential]) {
                        self.credentialState[provider][credential].status = 'error';
                    }
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
            $('input[type="url"]').each(function() {
                var $input = $(this);
                var value = $input.val().trim();
                
                if (value && !this.isValidUrl(value)) {
                    isValid = false;
                    return;
                }
            }.bind(this));
            
            // Validate email inputs
            $('input[type="email"]').each(function() {
                var $input = $(this);
                var value = $input.val().trim();
                
                if (value && !this.isValidEmail(value)) {
                    isValid = false;
                    return;
                }
            }.bind(this));
            
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
});