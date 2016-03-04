(function () {
    'use strict';
    //var serviceBase = 'http://localhost/AngularJSAuthentication.API/';
    //var serviceBase = 'http://localhost:26264/';
    var serviceBase = 'http://localhost:59823/';
    //var serviceBase = 'http://localhost:54150/';
    
    
    angular
        .module('custom')
        .constant('ngAuthSettings', {
            apiServiceBaseUri: serviceBase,
            clientId: 'ngAuthApp'
        });

})();