<?php $user_id = get_current_user_id();
$token         = Innocode\Cognito\User::get_token( $user_id ); ?>
<h2 id="inncognito"><?php _e( 'Inncognito', 'inncognito' ) ?></h2>
<table class="form-table" role="presentation">
	<tr class="inncognito-user-mfa-wrap">
		<th>
			<label for="inncognito-mfa"><?php _e( 'Multi-factor authentication (MFA)', 'inncognito' ) ?></label>
		</th>
		<td>
			<div class="hide-if-no-js">
				<button type="button" id="inncognito-mfa" disabled class="button button-secondary"><?php _e( 'Register New MFA Device', 'inncognito' ) ?></button>
				<span class="spinner <?= $token ? 'is-active' : '' ?>" style="float: none;"></span>
				<p class="description">
					<?php
					if ( $token ) {
						_e( '<strong>Warning:</strong> this action immediately disassociates the existing device, if any, from your account.', 'inncognito' );
					} else {
						printf(
							__( '<a href="%s">First you need to obtain a new access token from Cognito</a>.', 'inncognito' ),
							inncognito()->token_url( self_admin_url( 'profile.php#inncognito' ) )
						);
					}
					?>
				</p>
			</div>
		</td>
	</tr>
</table>
<script type="text/html" id="tmpl-inncognito-mfa-qr-code">
	<p class="description">
		<?php _e( 'Please scan the QR code or manually enter the key below it, then enter a one-time password from your preferred app to complete the setup.', 'inncognito' ) ?>
	</p>
	<p>
		<img src="{{ data.qr }}" width="200" height="200" alt="{{ data.uri }}">
	</p>
	<p>
		<code>{{ data.value }}</code>
	</p>
	<div>
		<label>
			<?php _e( 'One-time password:', 'inncognito' ) ?>
			<input type="tel" name="inncognito_mfa_user_code" class="input" size="20" pattern="[0-9]{6}">
		</label>
		<label>
			<?php _e( 'Device name (optional):', 'inncognito' ) ?>
			<input type="text" name="inncognito_mfa_user_device" class="input" size="20">
		</label>
		<?php submit_button( __( 'Submit' ), 'secondary', 'inncognito-mfa-qr-code-submit', false ) ?>
	</div>
</script>
<script type="text/html" id="tmpl-inncognito-profile">
	<p>
		<strong><?php _e( 'Current methods:', 'inncognito' ) ?></strong>
		<# if ( _.isArray( data.mfa ) && data.mfa.length ) { #>
			<# if ( _.contains( data.mfa, 'SOFTWARE_TOKEN_MFA' ) ) { #>
				<?php _e( 'Authenticator app', 'inncognito' ) ?>
			<# } #>
			<# if ( _.contains( data.mfa, 'SMS_MFA' ) ) { #>
				<?php _e( 'SMS', 'inncognito' ) ?>
			<# } #>
		<# } else { #>
			<?php _e( 'No methods', 'inncognito' ) ?>
		<# } #>
	</p>
</script>
