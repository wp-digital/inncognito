jQuery(function ($) {

    'use strict';

    var $button = $('#inncognito-mfa');
    var $spinner = $button.next('.spinner');

    var mfaQrCode = wp.template('inncognito-mfa-qr-code');
    var profile = wp.template('inncognito-profile');

    if ($spinner.hasClass('is-active')) {
        wp.apiRequest({
            path: '/innocode/v1/cognito/me'
        }).done(function (response) {
            $button.parent().append(profile(response));
            $spinner.removeClass('is-active');
            $button.prop('disabled', false);
        });
    }

    $button.on('click', function (event) {
        event.preventDefault();

        if ($spinner.hasClass('is-active')) {
            return;
        }

        $spinner.addClass('is-active');
        $button.prop('disabled', true);

        wp.apiRequest({
            path: '/innocode/v1/cognito/mfa/secret'
        }).done(function (response) {
            $button.parent().html(mfaQrCode(response));
        }).fail(function () {
            $spinner.removeClass('is-active');
            $button.prop('disabled', false);
        });
    });
});
