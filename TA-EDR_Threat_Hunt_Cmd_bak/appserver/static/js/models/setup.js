require([
    'jquery',
    'app/ta_edr_threat_hunt_cmd/js/setup_page'
], function(
    $,
    SetupPage
) {
    var setup = new SetupPage();
    setup.init();
});
