jQuery(function ($) {

    'use strict';

    var mfaQrCode = wp.template('inncognito-mfa-qr-code');

    $('#inncognito-mfa').on('click', function (event) {
        event.preventDefault();

        var $button = $(this);
        var $spinner = $button.next('.spinner');

        if ($spinner.hasClass('is-active')) {
            return;
        }

        $spinner.addClass('is-active');
        $button.prop('disabled', true);

        wp.apiRequest({
            path: '/innocode/v1/cognito/mfa/secret',
        }).done(function (response) {
            $button.parent().html(mfaQrCode(response));
        }).fail(function () {
            $spinner.removeClass('is-active');
            $button.prop('disabled', false);
        });
    });
});
