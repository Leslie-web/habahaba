var Login = function () {

    return {
        init: function () {
            $('.login').backstretch([
                    "/_public/images/bg/admin_login_bg.jpg"
                ], {
                    fade: 1000,
                    duration: 8000,
                    overlay: {
                        init: true
                    }
                }
            );
        }
    };

}();

jQuery(document).ready(function () {
    Login.init();
});