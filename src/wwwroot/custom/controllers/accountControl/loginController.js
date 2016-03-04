(function () {
    'use strict';

    angular
        .module('custom')
        .controller('LoginFormController', LoginFormController);

    LoginFormController.$inject = ['$scope','$state', '$log','$location', 'authService'];
    function LoginFormController($scope, $state, $log, $location, authService) {
        // for controllerAs syntax
        var vm = this;

        activate();

        ////////////////

        function activate() {
            vm.account = {
                userName: "",
                email: "",
                password: "",
                remember: ""
            };

            vm.authMsg = null;

            vm.login = function () {

                if (vm.account.userName == "")
                    vm.account.userName = vm.account.email;

                authService.login(vm.account).then(function (response) {

                    $state.go('app.welcome');

                },
                 function (err) {
                     var err_msg = "";
                     for (var i = 0; i < err.modelState[""].length; i++)
                         err_msg = err_msg == "" ? err.modelState[""][i] : (err_msg + ";" + err.modelState[""][i]);
                     vm.authMsg = err_msg;
                 });
            };
        }
    }
})();
