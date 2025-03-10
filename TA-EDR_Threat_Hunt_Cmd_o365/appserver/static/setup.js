require([
    'jquery',
    'splunkjs/mvc',
    'splunkjs/mvc/simplexml/ready!',
    'splunkjs/mvc/textinputview',
    'splunkjs/mvc/dropdownview',
    'splunkjs/mvc/checkboxview'
], function($, mvc, ready, TextInputView, DropdownView, CheckboxView) {

    console.log("Splunk MVC Components Loaded!");

    // Create setup container
    $('#setup-view').html(
        '<div class="control-group">' +
        '  <label for="log_level">Log Level</label>' +
        '  <div id="log_level_input"></div>' +
        '</div>' +
        '<div class="control-group">' +
        '  <label for="default_tenant">Default Tenant</label>' +
        '  <div id="default_tenant_input"></div>' +
        '</div>' +
        '<div class="control-group">' +
        '  <label for="enable_logging">Enable Detailed Logging</label>' +
        '  <div id="enable_logging_input"></div>' +
        '</div>' +
        '<div class="control-group">' +
        '  <button id="save_button" class="btn btn-primary">Save Configuration</button>' +  // ✅ Use a standard button
        '  <div id="status_message" style="margin-top: 10px;"></div>' +
        '</div>'
    );

    // Create form controls
    new DropdownView({
        id: "log_level",
        el: $('#log_level_input'),
        choices: [
            {label: "INFO", value: "INFO"},
            {label: "DEBUG", value: "DEBUG"},
            {label: "WARNING", value: "WARNING"},
            {label: "ERROR", value: "ERROR"}
        ],
        defaultValue: "INFO"
    }).render();

    new TextInputView({
        id: "default_tenant",
        el: $('#default_tenant_input'),
        defaultValue: "default"
    }).render();

    new CheckboxView({
        id: "enable_logging",
        el: $('#enable_logging_input'),
        value: true
    }).render();

    // Add CSS
    $('<style>')
        .prop('type', 'text/css')
        .html('.setup-container { max-width: 800px; margin: 0 auto; padding: 20px; }' +
              '.control-group { margin-bottom: 15px; }' +
              '.control-group label { display: block; font-weight: bold; margin-bottom: 5px; }' +
              '#status_message.success { color: green; } ' +
              '#status_message.error { color: red; }')
        .appendTo('head');

    var statusMessage = $('#status_message');

    // ✅ Handle Save Button Click with jQuery
    $("#save_button").on("click", function() {
        statusMessage.removeClass('success error').html('Saving configuration...');

        // Get form values
        var logLevel = mvc.Components.get("log_level").val();
        var defaultTenant = mvc.Components.get("default_tenant").val();
        var enableLogging = mvc.Components.get("enable_logging").val() ? "1" : "0";

        // Validate form
        if (!defaultTenant) {
            statusMessage.addClass('error').html('Default tenant is required!');
            return;
        }

        // Prepare data for REST API
        var data = {
            "log_level": logLevel,
            "default_tenant": defaultTenant,
            "enable_logging": enableLogging
        };

        // Save configuration using REST API
        $.ajax({
            url: "/splunkd/__raw/servicesNS/nobody/TA-EDR_Threat_Hunt_Cmd/TA-EDR_Threat_Hunt_Cmd_setup",
            type: "POST",
            data: data,
            success: function(response) {
                // Mark app as configured
                $.ajax({
                    url: "/splunkd/__raw/servicesNS/nobody/TA-EDR_Threat_Hunt_Cmd/configs/conf-app/install",
                    type: "POST",
                    data: {
                        "is_configured": "true"
                    },
                    success: function() {
                        statusMessage.addClass('success').html('Configuration saved successfully! Redirecting to home page...');
                        setTimeout(function() {
                            window.location.href = "/app/TA-EDR_Threat_Hunt_Cmd/home";
                        }, 2000);
                    },
                    error: function(xhr) {
                        statusMessage.addClass('error').html('Error marking app as configured: ' + xhr.responseText);
                    }
                });
            },
            error: function(xhr) {
                statusMessage.addClass('error').html('Error saving configuration: ' + xhr.responseText);
            }
        });
    });

    // Check if app is already configured
    $.ajax({
        url: "/splunkd/__raw/servicesNS/nobody/TA-EDR_Threat_Hunt_Cmd/configs/conf-app/install",
        type: "GET",
        dataType: "json",
        success: function(response) {
            if (response && response.entry && response.entry.length > 0) {
                var content = response.entry[0].content || {};
                if (content.is_configured === "true") {
                    // App is already configured, redirect to home
                    window.location.href = "/app/TA-EDR_Threat_Hunt_Cmd/home";
                }
            }
        }
    });

    // Load current settings if available
    $.ajax({
        url: "/splunkd/__raw/servicesNS/nobody/TA-EDR_Threat_Hunt_Cmd/setup",
        type: "GET",
        dataType: "json",
        success: function(response) {
            if (response && response.entry && response.entry.length > 0) {
                var content = response.entry[0].content || {};

                if (content.log_level) {
                    mvc.Components.get("log_level").val(content.log_level);
                }

                if (content.default_tenant) {
                    mvc.Components.get("default_tenant").val(content.default_tenant);
                }

                if (content.enable_logging !== undefined) {
                    mvc.Components.get("enable_logging").val(content.enable_logging === "1");
                }
            }
        }
    });
});
