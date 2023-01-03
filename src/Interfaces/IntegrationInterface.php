<?php

namespace Innocode\Cognito\Interfaces;

use Innocode\Cognito\Plugin;

interface IntegrationInterface {

	/**
	 * @param Plugin $plugin
	 * @return void
	 */
	public function run( Plugin $plugin ) : void;
}
