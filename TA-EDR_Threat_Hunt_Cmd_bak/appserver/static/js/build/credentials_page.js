require([
    'jquery',
    'underscore',
    'backbone',
    'splunkjs/mvc',
    'app/ta_edr_threat_hunt_cmd/js/build/main'
], function(
    $,
    _,
    Backbone,
    mvc,
    UCC
) {
    // Load the UCC credentials page
    var app_name = 'ta_edr_threat_hunt_cmd';
    
    // Initialize UCC configuration page
    $(document).ready(function() {
        // Load UCC credentials page
        UCC.init({
            page: 'credentials'
        });
    });
});
