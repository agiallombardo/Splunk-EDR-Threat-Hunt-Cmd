define([
    'jquery',
    'backbone',
    'splunkjs/mvc/utils',
    'util/splunkd_utils'
], function(
    $,
    Backbone,
    utils,
    splunkd_utils
) {
    var SetupModel = Backbone.Model.extend({
        url: '/splunkd/__raw/servicesNS/nobody/ta_edr_threat_hunt_cmd/ta_edr_threat_hunt_cmd_setup',
        
        defaults: {
            is_configured: false,
            log_level: 'INFO',
            default_tenant: 'default',
            enable_logging: '1'
        },
        
        initialize: function() {
            Backbone.Model.prototype.initialize.apply(this, arguments);
        },
        
        sync: function(method, model, options) {
            options = options || {};
            
            options.url = this.url;
            options.contentType = 'application/json';
            options.data = JSON.stringify(model.toJSON());
            options.type = 'POST';
            options.processData = false;
            
            return Backbone.sync.call(this, method, model, options);
        }
    });
    
    return SetupModel;
});
