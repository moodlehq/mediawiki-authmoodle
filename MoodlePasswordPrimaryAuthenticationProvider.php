<?php
/**
 * This program is a free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 * http://www.gnu.org/copyleft/gpl.html
 *
 * @file
 * @ingroup Auth
 */

namespace MediaWiki\Auth;

use MediaWiki\MediaWikiServices;
use MediaWiki\User\UserNameUtils;
use User;

/**
 * A primary authentication provider that authenticates the user against a remote Moodle site.
 *
 * @ingroup Auth
 * @since 1.27
 */
class MoodlePasswordPrimaryAuthenticationProvider extends AbstractPrimaryAuthenticationProvider {

	/** @var string The URL of the Moodle site we authenticate against. */
	protected $moodleUrl;

	/** @var array Array of (string) username => (string) email of users to become bureaucrats automatically on login. */
	protected $autoBureaucrats = [];

	/** @var array */
	protected $tokens = [];

	/** @var array */
	protected $userdata = [];

    /**
     * @param array $params Settings
     *  - moodleUrl: The URL of the Moodle site we authenticate against.
     */
    public function __construct( $params = [] ) {

		if ( empty( $params['moodleUrl'] ) ) {
			throw new \InvalidArgumentException( 'The moodleUrl parameter missing in the auth configuration' );
		}

		$this->moodleUrl = $params['moodleUrl'];
		$this->autoBureaucrats = $params['autoBureaucrats'] ?? [];
    }

	public function beginPrimaryAuthentication( array $reqs ) {
		$req = AuthenticationRequest::getRequestByClass( $reqs, PasswordAuthenticationRequest::class );
		if ( !$req ) {
			return AuthenticationResponse::newAbstain();
		}

		if ( $req->username === null || $req->password === null ) {
			return AuthenticationResponse::newAbstain();
		}

		$userNameUtils = MediaWikiServices::getInstance()->getUserNameUtils();
		$username = $userNameUtils->getCanonical( $req->username, UserNameUtils::RIGOR_USABLE );
		if ( $username === false ) {
			return AuthenticationResponse::newAbstain();
		}

		$token = $this->getMoodleUserToken( $req->username,  $req->password );

		if ( $token === false ) {
			return AuthenticationResponse::newAbstain();

		} else {
			$userinfo = $this->getMoodleUserInfo( $req->username, $token );

			if ( empty( $userinfo )) {
				$this->logger->error( 'AuthMoodle: Unable to obtain valid user info' );
				return AuthenticationResponse::newAbstain();
			}

			$this->userinfo[$username] = $userinfo;
			$this->tokens[$username] = $token;
			return AuthenticationResponse::newPass( $username );
		}
	}

	/**
	 * Prepares a curl handler to use for querying the Moodle web services.
	 *
	 * @param string $url
	 * @return resource
	 */
	protected function getMoodleCurlClient( $url ) {

		$curl = curl_init( $url );

		curl_setopt_array( $curl, [
			CURLOPT_USERAGENT => 'MWAuthMoodleBot/1.0',
			CURLOPT_NOBODY => false,
			CURLOPT_HEADER => false,
			CURLOPT_FOLLOWLOCATION => true,
			CURLOPT_MAXREDIRS => 10,
			CURLOPT_RETURNTRANSFER => true,
			CURLOPT_SSL_VERIFYPEER => 1,
			CURLOPT_SSL_VERIFYHOST => 2,
		]);

		return $curl;
	}

	/**
	 * Attempts to authenticate the user against Moodle and returns the auth token.
	 *
	 * @param string $username
	 * @param string $password
	 * @return string|bool False on error, token otherwise.
	 */
	protected function getMoodleUserToken( $username,  $password ) {

		$curl = $this->getMoodleCurlClient( $this->moodleUrl.'/login/token.php' );

		$params = http_build_query( [
			'username' => $username,
			'password' => $password,
			'service' => 'moodle_mobile_app',
		] );

		curl_setopt_array( $curl, [
			CURLOPT_POST => true,
			CURLOPT_POSTFIELDS => $params,
		]);

		$ret = curl_exec( $curl );
		$info = curl_getinfo( $curl );
		$error = curl_error( $curl );
		curl_close( $curl );

		if ( !empty( $error ) ) {
			$this->logger->error( 'AuthMoodle: cURL error: '.$error );
			return false;

		} else if ( $info['http_code'] != 200 ) {
			$this->logger->error( 'AuthMoodle: cURL error: unexpected HTTP response code '.$info['http_code'] );
			return false;

		} else {
			$decoded = @json_decode( $ret );
			if ( empty( $decoded ) ) {
				$this->logger->error( 'AuthMoodle: Unable to decode the JSON response: '.$ret );
				return false;
			}
		}

		if ( !empty( $decoded->token ) ) {
			return $decoded->token;

		} else if ( isset( $decoded->exception ) ) {
			$this->logger->error( 'AuthMoodle: Remote exception: '.$decoded->exception );
			return false;

		} else if ( isset( $decoded->error ) ) {
			$this->logger->error( 'AuthMoodle: Remote error: '.$decoded->error );
			return false;

		} else {
			$this->logger->error( 'AuthMoodle: Unknown error: '.$ret );
			return false;
		}
	}

    /**
     * @param null|\User $user
     * @param AuthenticationResponse $response
     */
    public function postAuthentication( $user, AuthenticationResponse $response ) {
		if ( $response->status !== AuthenticationResponse::PASS ) {
			return;
		}

		if ( empty( $this->tokens[$user->getName()] ) ) {
			$this->logger->error( 'AuthMoodle: Moodle token not found' );
			return;
		}

		$userinfo = $this->userinfo[$user->getName()] ?? null;

		if ( empty( $userinfo ) ) {
			$this->logger->error( 'AuthMoodle: Empty user info, skipping update ');
			return;
		}

		if ( $user->getRealName() === '' ) {
			// Set the user's real name if they are logging in for the first time. Also note MDLSITE-1293.
			$this->logger->debug( 'AuthMoodle: Setting the user real name' );
			$mwdbr = wfGetDB( DB_REPLICA );
			$realname = $userinfo->fullname;
			$counter = 1;
			while ( $mwdbr->selectField( 'user', 'user_name', ['user_real_name' => $realname] ) && $counter < 100 ) {
				$counter++;
				$realname = $userinfo->fullname.' '.$counter;
			}
			$user->setRealName( $realname );
		}

		$user->setEmail( $userinfo->email );
		$user->confirmEmail();
		$user->saveSettings();

		if ( ! empty( $this->autoBureaucrats[ $user->getName() ] ) ) {
			if ( $this->autoBureaucrats[ $user->getName() ] === 'unset' ) {
				MediaWikiServices::getInstance()
					->getUserGroupManager()
					->removeUserFromGroup( $user, 'bureaucrat' );

			} else if ( $this->autoBureaucrats[ $user->getName() ] === $user->getEmail() ) {
				MediaWikiServices::getInstance()
					->getUserGroupManager()
					->addUserToGroup( $user, 'bureaucrat' );
			}
		}
	}

	/**
	 * Loads the Moodle user's real name, email and username.
	 *
	 * @param string $username
	 * @param string $token
	 * @return object|bool
	 */
	protected function getMoodleUserInfo( $username, $token ) {

		$this->logger->debug( 'AuthMoodle: Attempting to get info about the user: '.$username.' using the token: '.$token );

		// Get the Moodle user id first.

		$params = http_build_query( [
			'wstoken' => $token,
			'wsfunction' => 'core_webservice_get_site_info',
			'moodlewsrestformat' => 'json',
		] );

		$curl = $this->getMoodleCurlClient( $this->moodleUrl.'/webservice/rest/server.php?'.$params );

		$ret = curl_exec( $curl );
		curl_close( $curl );

		$decoded = @json_decode( $ret );

		if ( empty( $decoded->userid ) ) {
			$this->logger->error( 'AuthMoodle: Unable to get Moodle user id' );
			return false;
		}

		if ( strtolower( $decoded->username ) !== strtolower( $username ) ) {
			$this->logger->error( 'AuthMoodle: User name mismatch' );
			return false;
		}

		$moodleuserid = $decoded->userid;

		// Get the user profile.

		$params = http_build_query( [
			'wstoken' => $token,
			'wsfunction' => 'core_user_get_users_by_field',
			'moodlewsrestformat' => 'json',
			'field' => 'id',
			'values' => [$moodleuserid],
		] );

		$curl = $this->getMoodleCurlClient( $this->moodleUrl.'/webservice/rest/server.php?'.$params );

		$ret = curl_exec( $curl );
		curl_close( $curl );

		$decoded = @json_decode( $ret );

		if ( empty( $decoded ) ) {
			$this->logger->error( 'AuthMoodle: Unable to get Moodle user profile' );
			return false;
		}

		if ( isset( $decoded->exception ) ) {
			$this->logger->error( 'AuthMoodle: Remote exception: '.$decoded->exception );
			return false;
		}

		return (object) [
			'fullname' => $decoded[0]->fullname,
			'email' => $decoded[0]->email,
			'username' => $decoded[0]->username,
		];
	}

	public function testUserCanAuthenticate( $username ) {
		return $this->testUserExists( $username );
	}

	public function testUserExists( $username, $flags = User::READ_NORMAL ) {
		// TODO - there is no easy way to do this without additional web services on the Moodle side.
		return false;
	}

	public function providerAllowsPropertyChange( $property ) {
		return false;
	}

	public function providerAllowsAuthenticationDataChange( AuthenticationRequest $req, $checkData = true) {
		return \StatusValue::newGood( 'ignored' );
	}

	public function providerChangeAuthenticationData( AuthenticationRequest $req ) {
		return;
	}

	public function accountCreationType() {
		return self::TYPE_CREATE;
	}

    public function beginPrimaryAccountCreation( $user, $creator, array $reqs ) {
		throw new \BadMethodCallException( 'This should not get called' );
	}

    public function getAuthenticationRequests( $action, array $options ) {
        switch ( $action ) {
            case AuthManager::ACTION_LOGIN:
                return [ new PasswordAuthenticationRequest() ];
            default:
                return [];
        }
    }
}
