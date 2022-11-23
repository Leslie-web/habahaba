var Login = function () {

    return {
        init: function () {
            $('.login').backstretch([
                    "/static/_public/images/bg/maize2.jpg"
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