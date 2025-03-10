require(['jquery', 'splunkjs/mvc/simplexml/ready!'], function($) {
    // Load the UCC configuration page
    var app_name = 'ta_edr_threat_hunt_cmd';
    var base_path = '/static/app/' + app_name + '/js/build/';
    
    // Load UCC configuration manager
    $(document).ready(function() {
        // Load CSS
        $('head').append('<link rel="stylesheet" type="text/css" href="' + base_path + 'custom/style.css">');
        
        // Load UCC main JS
        require([base_path + 'main'], function() {
            // UCC is now loaded
            console.log('UCC for ta_edr_threat_hunt_cmd loaded');
        });
    });
});
