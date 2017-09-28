# AuthMoodle

Extension for MediaWiki allowing to authenticate users against Moodle database via mobile app service.

## Requirements:

* MediaWiki 1.27+
* Moodle 3.1+ with mobile app service enabled

## Installation and setup

Clone / unzip into your MediaWiki's extension/AuthMoodle/ folder.

Configure your MediaWiki authentication manager to use this extension as the
primary authentication provider:

	wfLoadExtension( 'AuthMoodle' );

	$wgAuthManagerAutoConfig['primaryauth'] = [
		MediaWiki\Auth\MoodlePasswordPrimaryAuthenticationProvider::class => [
			'class' => MediaWiki\Auth\MoodlePasswordPrimaryAuthenticationProvider::class,
			'args' => [
				[
					'moodleUrl' => 'https://your.moodle.url',
				]
			],
			'sort' => 0,
		],
	];

## Copying

Copyright 2017 David Mudrák <david@moodle.org>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
