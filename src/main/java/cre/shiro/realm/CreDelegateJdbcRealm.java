/**
 * 
 */
package cre.shiro.realm;

import java.util.HashSet;
import java.util.Set;

import javax.annotation.Resource;

import org.apache.shiro.authc.AccountException;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.jdbc.JdbcRealm;
import org.apache.shiro.subject.PrincipalCollection;

import cre.domain.User;
import cre.repository.RoleToPermissionRepository;
import cre.repository.UserRepository;
import cre.repository.UserToRoleRepository;

/**
 * @author Cre.Gu
 * 
 */
public class CreDelegateJdbcRealm extends JdbcRealm {
	protected final org.slf4j.Logger log = org.slf4j.LoggerFactory
			.getLogger(CreDelegateJdbcRealm.class);

	@Resource
	private UserRepository userRepository;
	@Resource
	private UserToRoleRepository userToRoleRepository;
	@Resource
	private RoleToPermissionRepository roleToPermissionRepository;

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

		if (password == null) {
			throw new UnknownAccountException("No account found for user ["
					+ username + "]");
		}

		info = new SimpleAuthenticationInfo(username, password.toCharArray(),
				getName());

		return info;
	}

	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(
			PrincipalCollection principals) {

		if (principals == null) {
			throw new AuthorizationException(
					"PrincipalCollection method argument cannot be null.");
		}

		String username = (String) getAvailablePrincipal(principals);

		Set<String> roleNames = userToRoleRepository.findRoleName(username);
		Set<String> permissions = new HashSet<String>();

		for (String roleName : roleNames) {
			permissions.addAll(roleToPermissionRepository
					.findPermissions(roleName));
		}

		SimpleAuthorizationInfo info = new SimpleAuthorizationInfo(roleNames);
		info.setStringPermissions(permissions);
		return info;
	}

}
