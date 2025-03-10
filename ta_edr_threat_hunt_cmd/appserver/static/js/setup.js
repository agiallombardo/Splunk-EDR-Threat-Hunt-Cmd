/**
 * Setup script for ta_edr_threat_hunt_cmd
 * Based on the pattern from Splunk Add-on for Microsoft Office 365
 */
define([
    'jquery',
    'underscore',
    'backbone',
    'splunkjs/mvc',
    'splunkjs/mvc/utils'
], function($, _, Backbone, mvc, utils) {
    
    const APP_NAME = 'ta_edr_threat_hunt_cmd';
    
    /**
     * SetupView - Handles the setup and configuration of the app
     */
    const SetupView = Backbone.View.extend({
        initialize: function() {
            this._initializeGlobalConfig();
        },
        
        /**
         * Load the global configuration for the app
         */
        _initializeGlobalConfig: function() {
            const self = this;
            $.ajax({
                url: utils.make_url(`/static/app/${APP_NAME}/js/globalConfig.json`),
                type: 'GET',
                dataType: 'json',
                success: function(config) {
                    self.globalConfig = config;
                    self._checkAppState().then(function(isConfigured) {
                        if (isConfigured) {
                            self._renderConfigPage();
                        } else {
                            self._renderSetupPage();
                        }
                    });
                },
                error: function(err) {
                    console.error('Error loading global config:', err);
                    self._showErrorMessage('Error loading app configuration. Please check the browser console for details.');
                }
            });
        },
        
        /**
         * Check if the app is already configured
         */
        _checkAppState: function() {
            const deferred = $.Deferred();
            
            $.ajax({
                url: utils.make_url(`/splunkd/__raw/servicesNS/nobody/${APP_NAME}/apps/local/${APP_NAME}`),
                type: 'GET',
                dataType: 'json',
                data: {
                    output_mode: 'json'
                },
                success: function(data) {
                    const isConfigured = data && 
                                        data.entry && 
                                        data.entry.length > 0 && 
                                        data.entry[0].content.configured === '1';
                    deferred.resolve(isConfigured);
                },
                error: function() {
                    // If error, assume not configured
                    deferred.resolve(false);
                }
            });
            
            return deferred.promise();
        },
        
        /**
         * Mark the app as configured
         */
        _markAppConfigured: function() {
            $.ajax({
                url: utils.make_url(`/splunkd/__raw/servicesNS/nobody/${APP_NAME}/apps/local/${APP_NAME}`),
                type: 'POST',
                data: {
                    configured: '1'
                },
                success: function() {
                    // Reload to show configuration page
                    window.location.reload();
                },
                error: function(err) {
                    console.error('Error marking app as configured:', err);
                }
            });
        },
        
        /**
         * Render the initial setup page for first-time configuration
         */
        _renderSetupPage: function() {
            const self = this;
            
            // Clear content and show setup container
            this.$el.empty();
            const $setupContainer = $('<div class="setup-container"></div>');
            this.$el.append($setupContainer);
            
            // Add header
            $setupContainer.append('<h2>EDR Threat Hunt Command Setup</h2>');
            $setupContainer.append('<p>Configure settings to start using the app.</p>');
            
            // Create tabs for configuration
            this._renderConfigTabs($setupContainer, true);
            
            // Add setup button
            const $buttonContainer = $('<div class="button-container"></div>');
            const $setupButton = $('<button class="btn btn-primary" id="setup-button">Set Up</button>');
            $buttonContainer.append($setupButton);
            $setupContainer.append($buttonContainer);
            
            // Handle setup button click
            $setupButton.on('click', function() {
                self._handleSetup();
            });
        },
        
        /**
         * Render the configuration page for already configured apps
         */
        _renderConfigPage: function() {
            // Clear content and show config container
            this.$el.empty();
            const $configContainer = $('<div class="config-container"></div>');
            this.$el.append($configContainer);
            
            // Add header
            $configContainer.append('<h2>EDR Threat Hunt Command Configuration</h2>');
            $configContainer.append('<p>Configure and manage your app settings.</p>');
            
            // Create tabs for configuration
            this._renderConfigTabs($configContainer, false);
        },
        
        /**
         * Render configuration tabs based on globalConfig.json
         * Following the O365 add-on pattern
         */
        _renderConfigTabs: function($container, isSetup) {
            const self = this;
            
            // Create tabs container
            const $tabsContainer = $('<div class="tabs-container"></div>');
            const $tabList = $('<ul class="nav nav-tabs"></ul>');
            const $tabContent = $('<div class="tab-content"></div>');
            
            $tabsContainer.append($tabList);
            $tabsContainer.append($tabContent);
            $container.append($tabsContainer);
            
            // Get configuration pages
            const pages = this.globalConfig.pages.configuration.tabs;
            
            // Create a tab for each section
            _.each(pages, function(tabConfig, index) {
                // Create tab navigation item
                const isActive = index === 0 ? 'active' : '';
                const $tabNav = $(`<li class="${isActive}"><a href="#${tabConfig.name}" data-toggle="tab">${tabConfig.title}</a></li>`);
                $tabList.append($tabNav);
                
                // Create tab content
                const $tabPane = $(`<div class="tab-pane ${isActive}" id="${tabConfig.name}"></div>`);
                $tabContent.append($tabPane);
                
                // Handle different tab types
                if (tabConfig.table) {
                    // Table view (for collections like tenants, credentials)
                    self._renderTableView($tabPane, tabConfig, isSetup);
                } else {
                    // Entity view (for settings)
                    self._renderEntityView($tabPane, tabConfig, isSetup);
                }
            });
            
            // Bind tab click events
            $tabList.find('a').on('click', function(e) {
                e.preventDefault();
                $(this).tab('show');
            });
        },
        
        /**
         * Render entity view for settings
         */
        _renderEntityView: function($tabPane, tabConfig, isSetup) {
            const self = this;
            
            // Create entities (sections)
            _.each(tabConfig.entity, function(entityConfig) {
                const $entityContainer = $(`<div class="entity-container" id="entity-${entityConfig.name}"></div>`);
                $entityContainer.append(`<h3>${entityConfig.title}</h3>`);
                
                // Create form
                const $form = $(`<form class="entity-form" data-entity="${entityConfig.name}"></form>`);
                $entityContainer.append($form);
                
                // If not setup, load existing values
                if (!isSetup) {
                    self._loadEntityValues(entityConfig.name, function(values) {
                        self._renderEntityFields($form, entityConfig.field, values);
                        
                        // Add save button
                        const $saveButton = $('<button type="button" class="btn btn-primary entity-save">Save</button>');
                        $form.append($saveButton);
                        
                        // Handle save button
                        $saveButton.on('click', function() {
                            self._saveEntityValues($form, entityConfig.name);
                        });
                    });
                } else {
                    // For setup, just render with default values
                    self._renderEntityFields($form, entityConfig.field, {});
                }
                
                $tabPane.append($entityContainer);
            });
        },
        
        /**
         * Render table view for collections (tenants, credentials)
         */
        _renderTableView: function($tabPane, tabConfig, isSetup) {
            const self = this;
            
            // Create container for table
            const $tableContainer = $('<div class="table-container"></div>');
            $tabPane.append($tableContainer);
            
            // Add create button
            const $createButton = $('<button class="btn btn-primary" id="create-button">Add</button>');
            $tableContainer.append($createButton);
            
            // Create table
            const $table = $('<table class="table table-striped"></table>');
            const $tableHead = $('<thead></thead>');
            const $tableBody = $('<tbody></tbody>');
            
            $table.append($tableHead);
            $table.append($tableBody);
            $tableContainer.append($table);
            
            // Add table headers
            const $headerRow = $('<tr></tr>');
            _.each(tabConfig.table.header, function(header) {
                $headerRow.append(`<th>${header.label}</th>`);
            });
            // Add actions column
            $headerRow.append('<th>Actions</th>');
            $tableHead.append($headerRow);
            
            // If not setup, load collection items
            if (!isSetup) {
                self._loadCollectionItems(tabConfig.entity[0].name, function(items) {
                    // Render table rows
                    self._renderTableRows($tableBody, items, tabConfig);
                });
            }
            
            // Handle create button
            $createButton.on('click', function() {
                self._showEntityModal(tabConfig, null, 'create');
            });
        },
        
        /**
         * Render entity fields based on field configuration
         */
        _renderEntityFields: function($form, fieldConfigs, values) {
            _.each(fieldConfigs, function(field) {
                // Get field value
                const value = values[field.name] || field.defaultValue || '';
                
                // Create field container
                const $fieldContainer = $('<div class="form-group"></div>');
                $fieldContainer.append(`<label for="${field.name}">${field.label}</label>`);
                
                // Create different field types
                switch (field.type) {
                    case 'text':
                        $fieldContainer.append(`<input type="text" class="form-control" id="${field.name}" name="${field.name}" value="${value}">`);
                        break;
                    case 'password':
                        if (field.encrypted) {
                            // For encrypted fields, add a change checkbox
                            const $changeContainer = $('<div class="change-container"></div>');
                            const changeId = `change_${field.name}`;
                            $changeContainer.append(`
                                <div class="checkbox">
                                    <label>
                                        <input type="checkbox" id="${changeId}" name="${changeId}" value="1"> Change ${field.label}
                                    </label>
                                </div>
                            `);
                            $fieldContainer.append($changeContainer);
                            
                            // Add password field (initially hidden)
                            const $passwordField = $(`<input type="password" class="form-control" id="${field.name}" name="${field.name}" style="display:none;">`);
                            $fieldContainer.append($passwordField);
                            
                            // Show/hide password field based on checkbox
                            $changeContainer.find(`#${changeId}`).on('change', function() {
                                if ($(this).is(':checked')) {
                                    $passwordField.show();
                                } else {
                                    $passwordField.hide().val('');
                                }
                            });
                        } else {
                            $fieldContainer.append(`<input type="password" class="form-control" id="${field.name}" name="${field.name}">`);
                        }
                        break;
                    case 'checkbox':
                    case 'singleSelect':
                        // Implement other field types as needed
                        break;
                }
                
                // Add help text if available
                if (field.help) {
                    $fieldContainer.append(`<span class="help-block">${field.help}</span>`);
                }
                
                $form.append($fieldContainer);
            });
        },
        
        /**
         * Render table rows
         */
        _renderTableRows: function($tableBody, items, tabConfig) {
            const self = this;
            
            // Clear existing rows
            $tableBody.empty();
            
            // Add a row for each item
            _.each(items, function(item) {
                const $row = $('<tr></tr>');
                
                // Add columns
                _.each(tabConfig.table.header, function(header) {
                    $row.append(`<td>${item[header.field] || ''}</td>`);
                });
                
                // Add action buttons
                const $actionCell = $('<td></td>');
                
                // Edit button
                if (tabConfig.table.actions.includes('edit')) {
                    const $editButton = $('<button class="btn btn-sm btn-primary action-edit">Edit</button>');
                    $actionCell.append($editButton);
                    
                    $editButton.on('click', function() {
                        self._showEntityModal(tabConfig, item.name, 'edit');
                    });
                }
                
                // Delete button
                if (tabConfig.table.actions.includes('delete')) {
                    const $deleteButton = $('<button class="btn btn-sm btn-danger action-delete">Delete</button>');
                    $actionCell.append($deleteButton);
                    
                    $deleteButton.on('click', function() {
                        self._deleteCollectionItem(tabConfig.entity[0].name, item.name);
                    });
                }
                
                // Clone button
                if (tabConfig.table.actions.includes('clone')) {
                    const $cloneButton = $('<button class="btn btn-sm btn-default action-clone">Clone</button>');
                    $actionCell.append($cloneButton);
                    
                    $cloneButton.on('click', function() {
                        self._showEntityModal(tabConfig, item.name, 'clone');
                    });
                }
                
                $row.append($actionCell);
                $tableBody.append($row);
            });
        },
        
        /**
         * Load entity values from the backend
         */
        _loadEntityValues: function(entityName, callback) {
            $.ajax({
                url: utils.make_url(`/splunkd/__raw/servicesNS/nobody/${APP_NAME}/ta_edr_threat_hunt_cmd_settings/${entityName}`),
                type: 'GET',
                dataType: 'json',
                data: {
                    output_mode: 'json'
                },
                success: function(data) {
                    if (data && data.entry && data.entry.length > 0) {
                        callback(data.entry[0].content);
                    } else {
                        callback({});
                    }
                },
                error: function(err) {
                    console.error('Error loading entity values:', err);
                    callback({});
                }
            });
        },
        
        /**
         * Load collection items (tenants, credentials)
         */
        _loadCollectionItems: function(collectionName, callback) {
            $.ajax({
                url: utils.make_url(`/splunkd/__raw/servicesNS/nobody/${APP_NAME}/ta_edr_threat_hunt_cmd_${collectionName}`),
                type: 'GET',
                dataType: 'json',
                data: {
                    output_mode: 'json'
                },
                success: function(data) {
                    if (data && data.entry) {
                        const items = _.map(data.entry, function(entry) {
                            const item = {
                                name: entry.name
                            };
                            _.extend(item, entry.content);
                            return item;
                        });
                        callback(items);
                    } else {
                        callback([]);
                    }
                },
                error: function(err) {
                    console.error('Error loading collection items:', err);
                    callback([]);
                }
            });
        },
        
        /**
         * Save entity values
         */
        _saveEntityValues: function($form, entityName) {
            const formData = {};
            
            // Collect form data
            $form.find(':input').each(function() {
                const $input = $(this);
                const name = $input.attr('name');
                
                // Skip if no name attribute
                if (!name) return;
                
                // Handle different input types
                if ($input.attr('type') === 'checkbox') {
                    formData[name] = $input.is(':checked') ? '1' : '0';
                } else {
                    formData[name] = $input.val();
                }
            });
            
            // Save to backend
            $.ajax({
                url: utils.make_url(`/splunkd/__raw/servicesNS/nobody/${APP_NAME}/ta_edr_threat_hunt_cmd_settings/${entityName}`),
                type: 'POST',
                data: formData,
                success: function() {
                    // Show success message
                    alert('Settings saved successfully.');
                },
                error: function(err) {
                    console.error('Error saving settings:', err);
                    alert('Error saving settings. Please check the browser console for details.');
                }
            });
        },
        
        /**
         * Delete a collection item
         */
        _deleteCollectionItem: function(collectionName, itemName) {
            if (confirm(`Are you sure you want to delete ${itemName}?`)) {
                $.ajax({
                    url: utils.make_url(`/splunkd/__raw/servicesNS/nobody/${APP_NAME}/ta_edr_threat_hunt_cmd_${collectionName}/${itemName}`),
                    type: 'DELETE',
                    success: function() {
                        alert('Item deleted successfully.');
                        // Reload the page to reflect changes
                        window.location.reload();
                    },
                    error: function(err) {
                        console.error('Error deleting item:', err);
                        alert('Error deleting item. Please check the browser console for details.');
                    }
                });
            }
        },
        
        /**
         * Show modal for creating/editing/cloning an entity
         * This is a simplified placeholder - in a real implementation
         * you would create a proper modal dialog
         */
        _showEntityModal: function(tabConfig, itemName, mode) {
            alert(`This would show a modal to ${mode} ${itemName || 'a new item'}`);
            // In a real implementation, you would:
            // 1. Create a modal dialog
            // 2. Load entity data if editing/cloning
            // 3. Render form fields based on entity configuration
            // 4. Handle form submission
        },
        
        /**
         * Handle setup button click
         */
        _handleSetup: function() {
            // In a real implementation, you would:
            // 1. Validate all forms
            // 2. Save all configurations
            // 3. Mark the app as configured
            
            // For simplicity, just mark it as configured
            this._markAppConfigured();
        },
        
        /**
         * Show error message
         */
        _showErrorMessage: function(message) {
            this.$el.empty().append(`<div class="alert alert-danger">${message}</div>`);
        },
        
        render: function() {
            // Initial rendering is handled in initialize
            return this;
        }
    });
    
    // Initialize the setup view
    const setupView = new SetupView({
        el: $('#main-container')
    });
    setupView.render();
});