/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package cre.shiro.web.action;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.RequestMapping;

/**
 * 
 * @author Cre.Gu
 * 
 */
@Controller
public class LoginController {

	protected final org.slf4j.Logger log = org.slf4j.LoggerFactory
			.getLogger(LoginController.class);

	@RequestMapping(value = "/login")
	public String login(String username, String password,
			HttpServletRequest request, HttpServletResponse response,
			ModelMap model) {
		UsernamePasswordToken token = new UsernamePasswordToken(username,
				password);
		
		try {
			SecurityUtils.getSubject().login(token);
		} catch (AuthenticationException e) {
			log.debug("Error authenticating.", e);
			model.put("error.invalidLogin",
					"The username or password was not correct.");
			return "login";
		}

		return "index";
	}

}