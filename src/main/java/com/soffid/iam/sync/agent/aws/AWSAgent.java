package com.soffid.iam.sync.agent.aws;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.rmi.RemoteException;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.amazonaws.ClientConfiguration;
import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.auth.profile.ProfileCredentialsProvider;
import com.amazonaws.partitions.model.Region;
import com.amazonaws.regions.RegionUtils;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.identitymanagement.model.ChangePasswordRequest;
import com.amazonaws.services.identitymanagement.AmazonIdentityManagementClient;
import com.amazonaws.services.identitymanagement.model.AddUserToGroupRequest;
import com.amazonaws.services.identitymanagement.model.CreateGroupRequest;
import com.amazonaws.services.identitymanagement.model.CreateLoginProfileRequest;
import com.amazonaws.services.identitymanagement.model.CreateUserRequest;
import com.amazonaws.services.identitymanagement.model.DeleteGroupRequest;
import com.amazonaws.services.identitymanagement.model.DeleteLoginProfileRequest;
import com.amazonaws.services.identitymanagement.model.DeleteUserRequest;
import com.amazonaws.services.identitymanagement.model.GetGroupRequest;
import com.amazonaws.services.identitymanagement.model.GetGroupResult;
import com.amazonaws.services.identitymanagement.model.GetLoginProfileRequest;
import com.amazonaws.services.identitymanagement.model.GetLoginProfileResult;
import com.amazonaws.services.identitymanagement.model.GetRoleRequest;
import com.amazonaws.services.identitymanagement.model.GetRoleResult;
import com.amazonaws.services.identitymanagement.model.GetUserRequest;
import com.amazonaws.services.identitymanagement.model.GetUserResult;
import com.amazonaws.services.identitymanagement.model.Group;
import com.amazonaws.services.identitymanagement.model.ListGroupsForUserRequest;
import com.amazonaws.services.identitymanagement.model.ListGroupsForUserResult;
import com.amazonaws.services.identitymanagement.model.ListGroupsResult;
import com.amazonaws.services.identitymanagement.model.ListUsersResult;
import com.amazonaws.services.identitymanagement.model.NoSuchEntityException;
import com.amazonaws.services.identitymanagement.model.RemoveUserFromGroupRequest;
import com.amazonaws.services.identitymanagement.model.Role;
import com.amazonaws.services.identitymanagement.model.UpdateGroupRequest;
import com.amazonaws.services.identitymanagement.model.UpdateLoginProfileRequest;
import com.amazonaws.services.identitymanagement.model.UpdateUserRequest;
import com.amazonaws.services.identitymanagement.model.User;

import es.caib.seycon.ng.comu.Account;
import es.caib.seycon.ng.comu.Grup;
import es.caib.seycon.ng.comu.Password;
import es.caib.seycon.ng.comu.Rol;
import es.caib.seycon.ng.comu.RolGrant;
import es.caib.seycon.ng.comu.SoffidObjectType;
import es.caib.seycon.ng.comu.Usuari;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.exception.UnknownUserException;
import es.caib.seycon.ng.remote.RemoteServiceLocator;
import es.caib.seycon.ng.sync.agent.Agent;
import es.caib.seycon.ng.sync.engine.extobj.AccountExtensibleObject;
import es.caib.seycon.ng.sync.engine.extobj.AttributeReference;
import es.caib.seycon.ng.sync.engine.extobj.AttributeReferenceParser;
import es.caib.seycon.ng.sync.engine.extobj.ExtensibleObjectFinder;
import es.caib.seycon.ng.sync.engine.extobj.GroupExtensibleObject;
import es.caib.seycon.ng.sync.engine.extobj.MemberAttributeReference;
import es.caib.seycon.ng.sync.engine.extobj.ObjectTranslator;
import es.caib.seycon.ng.sync.engine.extobj.RoleExtensibleObject;
import es.caib.seycon.ng.sync.engine.extobj.UserExtensibleObject;
import es.caib.seycon.ng.sync.engine.extobj.ValueObjectMapper;
import es.caib.seycon.ng.sync.intf.AuthoritativeChange;
import es.caib.seycon.ng.sync.intf.AuthoritativeIdentitySource2;
import es.caib.seycon.ng.sync.intf.ExtensibleObject;
import es.caib.seycon.ng.sync.intf.ExtensibleObjectMapping;
import es.caib.seycon.ng.sync.intf.ExtensibleObjectMgr;
import es.caib.seycon.ng.sync.intf.ExtensibleObjects;
import es.caib.seycon.ng.sync.intf.GroupMgr;
import es.caib.seycon.ng.sync.intf.ReconcileMgr2;
import es.caib.seycon.ng.sync.intf.RoleMgr;
import es.caib.seycon.ng.sync.intf.UserMgr;

/**
 * Agente que gestiona los usuarios y contraseñas del LDAP Hace uso de las
 * librerias jldap de Novell
 * <P>
 * 
 * @author $Author: u88683 $
 * @version $Revision: 1.5 $
 */

public class AWSAgent extends Agent implements ExtensibleObjectMgr, UserMgr,
		ReconcileMgr2, GroupMgr, RoleMgr {

	private static final long serialVersionUID = 1L;

	ValueObjectMapper vom = new ValueObjectMapper();

	ObjectTranslator objectTranslator = null;

	boolean debugEnabled;

	private Collection<ExtensibleObjectMapping> objectMappings;

	private AWSCredentials credentials;

	private ClientConfiguration clientConfig;

	private String endpoint;

	/**
	 * Constructor
	 * 
	 * @param params
	 *            Parámetros de configuración: <li>0 = código de usuario LDAP</li>
	 *            <li>1 = contraseña de acceso LDAP</li> <li>2 = host</li> <li>3
	 *            = Nombre del attribute password</li> <li>4 = Algoritmo de hash
	 *            </li>
	 */
	public AWSAgent() throws RemoteException {
	}

	@Override
	public void init() throws InternalErrorException {
		log.info("Starting SCIM agent on {}", getDispatcher().getCodi(), null);

		
		credentials = new BasicAWSCredentials(getDispatcher().getParam0(),
				Password.decode(getDispatcher().getParam1()).getPassword());
		
        log.info ("Key   : "+getDispatcher().getParam0());
		log.info ("Secret: "+getDispatcher().getParam1());
		clientConfig = new ClientConfiguration();
		debugEnabled = "true".equals(getDispatcher().getParam2());
	}

	/************* PRIMITIVE AWS ACTIONS ***************************/
	private void updateGroupObject(ExtensibleObject obj) {
		AmazonIdentityManagementClient client = getAmazonClient();
		String groupName = vom.toSingleString(obj.getAttribute("groupName"));
		try {
			GetGroupResult resp = client
					.getGroup(new GetGroupRequest(groupName));

			Group awsGroup = resp.getGroup();
			awsGroup.setPath(vom.toSingleString(obj.getAttribute("path")));
			UpdateGroupRequest req = new UpdateGroupRequest(groupName);
			req.setNewPath(vom.toSingleString(obj.getAttribute("path")));
			client.updateGroup(req);
		} catch (NoSuchEntityException e) {
			CreateGroupRequest createGroupRequest = new CreateGroupRequest();
			createGroupRequest.setGroupName(groupName);
			createGroupRequest.setPath(vom.toSingleString(obj
					.getAttribute("path")));
			client.createGroup(createGroupRequest);
		}
	}

	private AmazonIdentityManagementClient getAmazonClient() {
		AmazonIdentityManagementClient client = new AmazonIdentityManagementClient(
				credentials);
		client.setEndpoint("https://iam.amazonaws.com");
		
		return client;
		
	}

	private void removeGroupObject(ExtensibleObject obj) {
		AmazonIdentityManagementClient client = getAmazonClient();
		String groupName = vom.toSingleString(obj.getAttribute("groupName"));
		try {
			GetGroupResult resp = client
					.getGroup(new GetGroupRequest(groupName));

			Group awsGroup = resp.getGroup();
			awsGroup.setPath(vom.toSingleString(obj.getAttribute("path")));
			client.deleteGroup(new DeleteGroupRequest(groupName));
		} catch (NoSuchEntityException e) {
		}
	}

	private void updateUserObject(ExtensibleObject obj, boolean setPassword) {
		AmazonIdentityManagementClient client = getAmazonClient();
		String userName = vom.toSingleString(obj.getAttribute("userName"));
		// Update or cretae user
		try {
			GetUserRequest r = new GetUserRequest();
			r.setUserName(userName);
			GetUserResult resp = client.getUser(r);

			UpdateUserRequest r2 = new UpdateUserRequest(userName);
			r2.setNewPath(vom.toSingleString(obj.getAttribute("path")));
			client.updateUser(r2);
		} catch (NoSuchEntityException e) {
			CreateUserRequest createUserRequest = new CreateUserRequest();
			createUserRequest.setUserName(userName);
			createUserRequest.setPath(vom.toSingleString(obj
					.getAttribute("path")));
			client.createUser(createUserRequest);
			setPassword = true;
		}
		if (setPassword && obj.containsKey("password")) {
			try {
				UpdateLoginProfileRequest clpr = new UpdateLoginProfileRequest(
						userName);
				clpr.setPassword(vom.toSingleString(obj
						.getAttribute("password")));
				if (obj.containsKey("mustChange"))
					clpr.setPasswordResetRequired(vom.toBoolean(obj
							.getAttribute("mustChange")));
				client.updateLoginProfile(clpr);
			} catch (NoSuchEntityException e) {
				CreateLoginProfileRequest clpr = new CreateLoginProfileRequest(
						userName, vom.toSingleString(obj
								.getAttribute("password")));
				if (obj.containsKey("mustChange"))
					clpr.setPasswordResetRequired(vom.toBoolean(obj
							.getAttribute("mustChange")));
				client.createLoginProfile(clpr);
			}
		}
	}

	private void updateUserObjectGroups(Account acc)
			throws InternalErrorException {
		AmazonIdentityManagementClient client = getAmazonClient();
		String accountName = acc.getName();
		ListGroupsForUserResult groups = client
				.listGroupsForUser(new ListGroupsForUserRequest(accountName));
		Collection<RolGrant> grants = getServer().getAccountRoles(
				acc.getName(), acc.getDispatcher());

		Set<String> groupsToAdd = new HashSet<String>();
		Set<String> groupsToRemove = new HashSet<String>();

		for (RolGrant grant : grants)
			groupsToAdd.add(grant.getRolName());
		for (Group g : groups.getGroups()) {
			groupsToRemove.add(g.getGroupName());
		}

		for (String groupToAdd : groupsToAdd) {
			if (groupsToRemove.contains(groupToAdd)) {
				groupsToRemove.remove(groupToAdd);
			} else {
				client.addUserToGroup(new AddUserToGroupRequest(groupToAdd,
						accountName));
			}
		}

		for (String groupToRemove : groupsToRemove) {
			client.removeUserFromGroup(new RemoveUserFromGroupRequest(
					groupToRemove, accountName));
		}

	}

	private void removeUserObject(ExtensibleObject obj) {
		AmazonIdentityManagementClient client = getAmazonClient();
		String userName = vom.toSingleString(obj.getAttribute("userName"));
		// 1. Remove login profile
		try {
			DeleteLoginProfileRequest req = new DeleteLoginProfileRequest(
					userName);
			client.deleteLoginProfile(req);
		} catch (NoSuchEntityException e) {
			// Login profile does not exist
		}
		// 2. Remove user
		try {
			client.deleteUser(new DeleteUserRequest(userName));
		} catch (NoSuchEntityException e) {
			// User does not exist
		}
	}

	public void removeRole(String name, String system) throws RemoteException,
			InternalErrorException {
		Rol rol = new Rol();
		rol.setNom(name);
		if (getCodi().equals(system)) {
			rol.setBaseDeDades(system);

			ExtensibleObject roleObject = new RoleExtensibleObject(rol,
					getServer());
			try {
				for (ExtensibleObjectMapping eom : objectMappings) {
					if (eom.getSoffidObject().equals(
							SoffidObjectType.OBJECT_ROLE)) {
						if (!"true".equals(eom.getProperties().get(
								"preventDeletion"))) {
							String condition = eom.getCondition();
							eom.setCondition(null);
							try {
								ExtensibleObject obj = objectTranslator
										.generateObject(roleObject, eom);
								if (obj != null)
									removeGroupObject(obj);
							} finally {
								eom.setCondition(condition);
							}
						}
					}
				}
			} catch (InternalErrorException e) {
				throw e;
			} catch (Exception e) {
				throw new InternalErrorException(e.getMessage(), e);
			}
		}
	}

	public void updateRole(Rol rol) throws RemoteException,
			InternalErrorException {
		if (rol.getBaseDeDades().equals(getDispatcher().getCodi())) {
			try {
				RoleExtensibleObject sourceObject = new RoleExtensibleObject(
						rol, getServer());
				debugObject("Updating role", sourceObject, "");

				for (ExtensibleObjectMapping mapping : objectMappings) {
					if (mapping.getSoffidObject().equals(
							SoffidObjectType.OBJECT_ROLE)) {
						if (objectTranslator.evalCondition(sourceObject,
								mapping)) {
							ExtensibleObject obj = objectTranslator
									.generateObject(sourceObject, mapping);
							if (obj != null)
								updateGroupObject(obj);
						} else {
							removeRole(rol.getNom(), rol.getBaseDeDades());
						}
					}
				}
			} catch (InternalErrorException e) {
				throw e;
			} catch (Exception e) {
				throw new InternalErrorException(e.getMessage(), e);
			}
		}
	}

	public void removeGroup(String name) throws RemoteException,
			InternalErrorException {
		Grup grup = new Grup();
		grup.setCodi(name);
		GroupExtensibleObject groupObject = new GroupExtensibleObject(grup,
				getDispatcher().getCodi(), getServer());
		try {
			for (ExtensibleObjectMapping eom : objectMappings) {
				if (!"true".equals(eom.getProperties().get("preventDeletion"))) {
					String condition = eom.getCondition();
					eom.setCondition(null);
					try {
						ExtensibleObject obj = objectTranslator.generateObject(
								groupObject, eom);
						if (obj != null)
							removeGroupObject(obj);
					} finally {
						eom.setCondition(condition);
					}
				}
			}
		} catch (InternalErrorException e) {
			throw e;
		} catch (Exception e) {
			throw new InternalErrorException(e.getMessage(), e);
		}
	}

	public void updateGroup(String name, Grup group) throws RemoteException,
			InternalErrorException {

		try {
			GroupExtensibleObject sourceObject = new GroupExtensibleObject(
					group, getCodi(), getServer());
			for (ExtensibleObjectMapping mapping : objectMappings) {
				if (mapping.getSoffidObject().equals(
						SoffidObjectType.OBJECT_GROUP)) {
					if (objectTranslator.evalCondition(sourceObject, mapping)) {
						ExtensibleObject obj = objectTranslator.generateObject(
								sourceObject, mapping);
						if (obj != null)
							updateGroupObject(obj);
					} else {
						removeGroup(name);
					}
				}
			}
		} catch (InternalErrorException e) {
			throw e;
		} catch (Exception e) {
			throw new InternalErrorException(e.getMessage(), e);
		}
	}

	public List<RolGrant> getAccountGrants(String accountName)
			throws RemoteException, InternalErrorException {
		AmazonIdentityManagementClient client = getAmazonClient();
		String userName = vom.toSingleString(accountName);
		ListGroupsForUserResult groups = client
				.listGroupsForUser(new ListGroupsForUserRequest(accountName));

		List<RolGrant> grants = new LinkedList<RolGrant>();

		for (Group g : groups.getGroups()) {
			RolGrant rg = new RolGrant();
			rg.setDispatcher(getCodi());
			rg.setOwnerAccountName(accountName);
			rg.setOwnerDispatcher(accountName);
			rg.setRolName(g.getGroupName());
			grants.add(rg);
		}
		return grants;
	}

	public Account getAccountInfo(String accountName) throws RemoteException,
			InternalErrorException {
		AmazonIdentityManagementClient client = getAmazonClient();
		for (ExtensibleObjectMapping mapping : objectMappings) {
			if (mapping.getSoffidObject().equals(
					SoffidObjectType.OBJECT_ACCOUNT)) {
				GetUserRequest req = new GetUserRequest();
				req.setUserName(accountName);
				try {
					GetUserResult resp = client.getUser(req);
					ExtensibleObject eo = new ExtensibleObject();
					eo.setObjectType(mapping.getSystemObject());
					eo.setAttribute("userName", resp.getUser().getUserId());
					eo.setAttribute("arn", resp.getUser().getArn());
					eo.setAttribute("createDate", resp.getUser()
							.getCreateDate());
					eo.setAttribute("passwordLastUsed", resp.getUser()
							.getPasswordLastUsed());
					eo.setAttribute("path", resp.getUser().getPath());
					eo.setAttribute("userId", resp.getUser().getUserId());
					debugObject("Parsed object", eo, "  ");
					Account acc = vom.parseAccount(objectTranslator
							.parseInputObject(eo, mapping));
					if (debugEnabled)
						log.info("Resulting account: " + acc.toString());
					if (acc != null)
						return acc;
				} catch (NoSuchEntityException e) {

				}
			}
		}
		return null;
	}

	public List<String> getAccountsList() throws RemoteException,
			InternalErrorException {
		AmazonIdentityManagementClient client = getAmazonClient();
		ListUsersResult users = client.listUsers();

		List<String> accounts = new LinkedList<String>();

		for (User u : users.getUsers()) {
			accounts.add(u.getUserName());
		}
		return accounts;
	}

	public Rol getRoleFullInfo(String roleName) throws RemoteException,
			InternalErrorException {
		AmazonIdentityManagementClient client = getAmazonClient();
		for (ExtensibleObjectMapping mapping : objectMappings) {
			if (mapping.getSoffidObject().equals(SoffidObjectType.OBJECT_ROLE)) {
				GetGroupRequest req = new GetGroupRequest();
				req.setGroupName(roleName);
				try {
					GetGroupResult resp = client.getGroup(req);
					ExtensibleObject eo = new ExtensibleObject();
					eo.setObjectType(mapping.getSystemObject());
					eo.setAttribute("groupName", resp.getGroup().getGroupName());
					eo.setAttribute("arn", resp.getGroup().getArn());
					eo.setAttribute("createDate", resp.getGroup()
							.getCreateDate());
					eo.setAttribute("path", resp.getGroup().getPath());
					eo.setAttribute("groupId", resp.getGroup().getGroupId());
					debugObject("Parsed object", eo, "  ");
					ExtensibleObject eso = objectTranslator.parseInputObject(
							eo, mapping);
					debugObject("Soffid object", eso, "  ");
					Rol role = vom.parseRol(eso);
					if (debugEnabled)
						log.info("Resulting role: " + role.toString());
					if (role != null)
						return role;
				} catch (NoSuchEntityException e) {

				}
			}
		}
		return null;
	}

	public List<String> getRolesList() throws RemoteException,
			InternalErrorException {
		AmazonIdentityManagementClient client = getAmazonClient();
		ListGroupsResult users = client.listGroups();

		List<String> roleNames = new LinkedList<String>();

		for (Group g : users.getGroups()) {
			roleNames.add(g.getGroupName());
		}
		return roleNames;
	}

	public void removeUser(String accountName) throws RemoteException,
			InternalErrorException {
		Account acc = getServer().getAccountInfo(accountName, getCodi());
		if (acc == null) {
			removeScimUser(accountName);
		} else {
			try {
				Usuari u = getServer().getUserInfo(accountName, getCodi());
				updateUser(acc, u);
			} catch (UnknownUserException e) {
				updateUser(acc);
			}
		}
	}

	public void removeScimUser(String accountName) throws RemoteException,
			InternalErrorException {
		Account acc = new Account();
		acc.setName(accountName);
		acc.setDispatcher(getCodi());
		ExtensibleObject userObject = new AccountExtensibleObject(acc,
				getServer());
		try {
			for (ExtensibleObjectMapping eom : objectMappings) {
				if (!"true".equals(eom.getProperties().get("preventDeletion"))) {
					String condition = eom.getCondition();
					eom.setCondition(null);
					try {
						ExtensibleObject obj = objectTranslator.generateObject(
								userObject, eom);
						if (obj != null)
							removeUserObject(obj);
					} finally {
						eom.setCondition(condition);
					}
				}
			}
		} catch (InternalErrorException e) {
			throw e;
		} catch (Exception e) {
			throw new InternalErrorException(e.getMessage(), e);
		}
	}

	public void updateUser(Account acc, Usuari user) throws RemoteException,
			InternalErrorException {
		ExtensibleObject sourceObject = new UserExtensibleObject(acc, user,
				getServer());
		try {
			for (ExtensibleObjectMapping mapping : objectMappings) {
				if (mapping.getSoffidObject().equals(
						SoffidObjectType.OBJECT_USER)) {
					if (objectTranslator.evalCondition(sourceObject, mapping)) {
						ExtensibleObject obj = objectTranslator.generateObject(
								sourceObject, mapping);
						obj.setAttribute(
								"password",
								getServer().getOrGenerateUserPassword(
										acc.getName(), getCodi()));
						obj.setAttribute("mustChange", Boolean.FALSE);
						if (obj != null)
							updateUserObject(obj, false);
						updateUserObjectGroups(acc);
					} else {
						removeScimUser(acc.getName());
					}
				}
			}
		} catch (InternalErrorException e) {
			throw e;
		} catch (Exception e) {
			throw new InternalErrorException(e.getMessage(), e);
		}
	}

	public void updateUser(Account acc) throws InternalErrorException {

		ExtensibleObject sourceObject = new AccountExtensibleObject(acc,
				getServer());
		try {
			for (ExtensibleObjectMapping mapping : objectMappings) {
				if (mapping.getSoffidObject().equals(
						SoffidObjectType.OBJECT_ACCOUNT)) {
					if (objectTranslator.evalCondition(sourceObject, mapping)) {
						ExtensibleObject obj = objectTranslator.generateObject(
								sourceObject, mapping);
						if (obj != null) {
							obj.setAttribute(
									"password",
									getServer().getOrGenerateUserPassword(
											acc.getName(), getCodi()));
							obj.setAttribute("mustChange", Boolean.FALSE);
							updateUserObject(obj, false);
							updateUserObjectGroups(acc);
						}
					} else {
						removeScimUser(acc.getName());
					}
				}
			}
		} catch (InternalErrorException e) {
			throw e;
		} catch (Exception e) {
			throw new InternalErrorException(e.getMessage(), e);
		}
	}

	public void updateUserPassword(String accountName, Usuari user,
			Password password, boolean mustChange) throws RemoteException,
			InternalErrorException {
		Account acc = new Account();
		acc.setName(accountName);
		if (user != null)
			acc.setDescription(user.getFullName());
		acc.setDispatcher(getCodi());
		ExtensibleObject object = user == null ? new AccountExtensibleObject(
				acc, getServer()) : new UserExtensibleObject(acc, user,
				getServer());
		ExtensibleObjects objects = objectTranslator.generateObjects(object);
		try {
			for (ExtensibleObject object2 : objects.getObjects()) {
				object2.setAttribute("password", password.getPassword());
				object2.setAttribute("mustChange", mustChange);
				updateUserObject(object2, true);
			}
			updateUserObjectGroups(acc);
		} catch (Exception e) {
			throw new InternalErrorException(e.getMessage(), e);
		}
	}

	public boolean validateUserPassword(String arg0, Password arg1)
			throws RemoteException, InternalErrorException {
		return false;
	}

	public void configureMappings(Collection<ExtensibleObjectMapping> mapping)
			throws RemoteException, InternalErrorException {
		this.objectMappings = mapping;
		this.objectTranslator = new ObjectTranslator(getDispatcher(),
				getServer(), mapping);
	}

	private String getJsonReference(AttributeReference ar) {
		String ft = null;
		while (ar != null) {
			if (ar instanceof MemberAttributeReference) {
				if (ft == null)
					ft = ((MemberAttributeReference) ar).getMember();
				else
					ft = ((MemberAttributeReference) ar).getMember() + "." + ft;
			}
			ar = ar.getParentReference();
		}
		return ft;
	}

	private ExtensibleObjectMapping getMapping(String objectType) {
		for (ExtensibleObjectMapping map : objectMappings) {
			if (map.getSystemObject().equals(objectType))
				return map;
		}
		return null;
	}

	void debugObject(String msg, Object obj, String indent) {
		debugObject(msg, obj, indent, "");
	}

	void debugObject(String msg, Object obj, String indent, String attributeName) {
		if (debugEnabled) {
			if (msg != null)
				log.info(indent + msg);
			if (obj == null) {
				log.info(indent + attributeName.toString() + ": null");
			} else if (obj instanceof List) {
				log.info(indent + attributeName + "List [");
				List l = (List) obj;
				int i = 0;
				for (Object subObj2 : l) {
					debugObject(null, subObj2, indent + "   ", "" + (i++)
							+ ": ");
				}
				log.info(indent + "]");

			} else if (obj instanceof Map) {
				log.info(indent + attributeName + ":");
				Map<String, Object> m = (Map<String, Object>) obj;
				for (String attribute : m.keySet()) {
					Object subObj = m.get(attribute);
					debugObject(null, subObj, indent + "   ", attribute + ": ");
				}
			} else {
				log.info(indent + attributeName.toString() + obj.toString());
			}
		}
	}

	/**
	 * Actualizar los datos del usuario. Crea el usuario en la base de datos y
	 * le asigna una contraseña aleatoria. <BR>
	 * Da de alta los roles<BR>
	 * Le asigna los roles oportuno.<BR>
	 * Le retira los no necesarios.
	 * 
	 * @param user
	 *            código de usuario
	 * @throws java.rmi.RemoteException
	 *             error de comunicaciones con el servidor
	 * @throws InternalErrorException
	 *             cualquier otro problema
	 */
	public void updateUser(String account, Usuari usu)
			throws java.rmi.RemoteException,
			es.caib.seycon.ng.exception.InternalErrorException {
		Account acc = getServer().getAccountInfo(account, getCodi());
		updateUser(acc, usu);
	}

	public void updateUser(String account, String descripcio)
			throws RemoteException,
			es.caib.seycon.ng.exception.InternalErrorException {
		Account acc = getServer().getAccountInfo(account, getCodi());
		if (acc == null)
			removeScimUser(account);
		else
			updateUser(acc);

	}

}
