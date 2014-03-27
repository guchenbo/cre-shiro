/**
 * 
 */
package cre.shiro.realm;

import java.sql.SQLException;

import javax.annotation.Resource;

import org.apache.shiro.authc.AccountException;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.config.ConfigurationException;
import org.apache.shiro.realm.jdbc.JdbcRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;
import org.apache.shiro.util.JdbcUtils;

import cre.domain.User;
import cre.repository.UserRepository;

/**
 * @author Cre.Gu
 * 
 */
public class CreDelegateJdbcRealm extends JdbcRealm {
	protected final org.slf4j.Logger log = org.slf4j.LoggerFactory
			.getLogger(CreDelegateJdbcRealm.class);

	@Resource
	private UserRepository userRepository;

	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(
			AuthenticationToken token) throws AuthenticationException {
		UsernamePasswordToken upToken = (UsernamePasswordToken) token;
		String username = upToken.getUsername();

		// Null username is invalid
		if (username == null) {
			throw new AccountException(
					"Null usernames are not allowed by this realm.");
		}

		SimpleAuthenticationInfo info = null;

		User user = userRepository.findByUsername(username);

		String password = user.getPassword();
		String salt = null;

		if (password == null) {
			throw new UnknownAccountException("No account found for user ["
					+ username + "]");
		}

		info = new SimpleAuthenticationInfo(username, password.toCharArray(),
				getName());

		if (salt != null) {
			info.setCredentialsSalt(ByteSource.Util.bytes(salt));
		}

		return info;
	}

	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(
			PrincipalCollection principals) {
		// TODO Auto-generated method stub
		return super.doGetAuthorizationInfo(principals);
	}

}
