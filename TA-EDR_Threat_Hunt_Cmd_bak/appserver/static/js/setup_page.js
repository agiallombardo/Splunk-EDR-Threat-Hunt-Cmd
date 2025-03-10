define([
    'jquery',
    'underscore',
    'backbone',
    'splunkjs/mvc',
    'splunkjs/mvc/simplesplunkview',
    'app/TA-EDR_Threat_Hunt_Cmd/js/models/setup',
    'splunkjs/mvc/utils',
    'util/splunkd_utils',
    'splunkjs/mvc/tokenutils',
    'splunkjs/mvc/simpleform/input/text',
    'splunkjs/mvc/simpleform/input/dropdown',
    'splunkjs/mvc/simpleform/input/submit',
    'splunkjs/mvc/simplexml/ready!'
], function(
    $,
    _,
    Backbone,
    mvc,
    SimpleSplunkView,
    SetupModel,
    utils,
    splunkd_utils,
    token_utils,
    TextInput,
    DropdownInput,
    SubmitButton
) {
    var SetupPage = SimpleSplunkView.extend({
        className: "SetupPage",
        
        initialize: function() {
            SimpleSplunkView.prototype.initialize.apply(this, arguments);
            this.setupModel = new SetupModel();
        },
        
        events: {
            "click #save-config": "saveConfig"
        },
        
        render: function() {
            // Check if app is configured
            var self = this;
            this.setupModel.fetch()
                .done(function() {
                    if (self.setupModel.get('is_configured')) {
                        // App is already configured, redirect to home
                        window.location.href = '/app/ta_edr_threat_hunt_cmd/home';
                    } else {
                        // App needs setup, show form
                        self.renderSetupForm();
                    }
                })
                .fail(function(error) {
                    console.error("Failed to fetch setup state:", error);
                    self.renderSetupForm();
                });
            
            return this;
        },
        
        renderSetupForm: function() {
            // Add setup form to the page
            var html = '<div class="setup-container">' + 
                       '<h2>EDR Threat Hunt Command Setup</h2>' + 
                       '<div class="control-group">' +
                       '<label for="log_level">Log Level</label>' +
                       '<div id="log_level"></div>' +
                       '</div>' +
                       '<div class="control-group">' +
                       '<label for="default_tenant">Default Tenant</label>' +
                       '<div id="default_tenant"></div>' +
                       '</div>' +
                       '<div class="control-group">' +
                       '<label for="enable_logging">Enable Detailed Logging</label>' +
                       '<div id="enable_logging"></div>' +
                       '</div>' +
                       '<div class="control-group">' +
                       '<div id="save-button"></div>' +
                       '</div>' +
                       '</div>';
            
            this.$el.html(html);
            
            // Create inputs
            new DropdownInput({
                id: "log_level",
                el: this.$('#log_level'),
                choices: [
                    { label: "INFO", value: "INFO" },
                    { label: "DEBUG", value: "DEBUG" },
                    { label: "WARNING", value: "WARNING" },
                    { label: "ERROR", value: "ERROR" }
                ],
                default: "INFO"
            }).render();
            
            new TextInput({
                id: "default_tenant",
                el: this.$('#default_tenant'),
                default: "default"
            }).render();
            
            new DropdownInput({
                id: "enable_logging",
                el: this.$('#enable_logging'),
                choices: [
                    { label: "Yes", value: "1" },
                    { label: "No", value: "0" }
                ],
                default: "1"
            }).render();
            
            new SubmitButton({
                id: "save-config",
                el: this.$('#save-button'),
                label: "Save Configuration"
            }).render();
            
            return this;
        },
        
        saveConfig: function(e) {
            e.preventDefault();
            
            var log_level = mvc.Components.get("log_level").val();
            var default_tenant = mvc.Components.get("default_tenant").val();
            var enable_logging = mvc.Components.get("enable_logging").val();
            
            // Validate
            if (!default_tenant) {
                alert("Default tenant is required!");
                return;
            }
            
            // Save config
            this.setupModel.save({
                log_level: log_level,
                default_tenant: default_tenant,
                enable_logging: enable_logging
            }).done(function() {
                // Success, redirect to home
                alert("Configuration saved successfully!");
                window.location.href = '/app/TA-EDR_Threat_Hunt_Cmd/home';
            }).fail(function(response) {
                console.error("Failed to save configuration:", response);
                alert("Failed to save configuration. Check console for details.");
            });
        },
        
        init: function() {
            this.render();
            return this;
        }
    });
    
    return SetupPage;
});
