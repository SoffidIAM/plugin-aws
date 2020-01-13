package com.soffid.iam.sync.agent.aws;

import java.lang.reflect.InvocationTargetException;
import java.rmi.RemoteException;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.commons.beanutils.PropertyUtils;

import com.amazonaws.ClientConfiguration;
import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.services.identitymanagement.AmazonIdentityManagementClient;
import com.amazonaws.services.identitymanagement.model.AccessKeyMetadata;
import com.amazonaws.services.identitymanagement.model.AddUserToGroupRequest;
import com.amazonaws.services.identitymanagement.model.CreateGroupRequest;
import com.amazonaws.services.identitymanagement.model.CreateLoginProfileRequest;
import com.amazonaws.services.identitymanagement.model.CreateUserRequest;
import com.amazonaws.services.identitymanagement.model.DeleteAccessKeyRequest;
import com.amazonaws.services.identitymanagement.model.DeleteGroupRequest;
import com.amazonaws.services.identitymanagement.model.DeleteLoginProfileRequest;
import com.amazonaws.services.identitymanagement.model.DeleteUserRequest;
import com.amazonaws.services.identitymanagement.model.GetGroupRequest;
import com.amazonaws.services.identitymanagement.model.GetGroupResult;
import com.amazonaws.services.identitymanagement.model.GetUserRequest;
import com.amazonaws.services.identitymanagement.model.GetUserResult;
import com.amazonaws.services.identitymanagement.model.Group;
import com.amazonaws.services.identitymanagement.model.ListAccessKeysRequest;
import com.amazonaws.services.identitymanagement.model.ListAccessKeysResult;
import com.amazonaws.services.identitymanagement.model.ListGroupsForUserRequest;
import com.amazonaws.services.identitymanagement.model.ListGroupsForUserResult;
import com.amazonaws.services.identitymanagement.model.ListGroupsResult;
import com.amazonaws.services.identitymanagement.model.ListUsersResult;
import com.amazonaws.services.identitymanagement.model.NoSuchEntityException;
import com.amazonaws.services.identitymanagement.model.RemoveUserFromGroupRequest;
import com.amazonaws.services.identitymanagement.model.UpdateGroupRequest;
import com.amazonaws.services.identitymanagement.model.UpdateLoginProfileRequest;
import com.amazonaws.services.identitymanagement.model.UpdateUserRequest;
import com.amazonaws.services.identitymanagement.model.User;

import es.caib.seycon.ng.comu.Account;
import es.caib.seycon.ng.comu.Grup;
import es.caib.seycon.ng.comu.ObjectMappingTrigger;
import es.caib.seycon.ng.comu.Password;
import es.caib.seycon.ng.comu.Rol;
import es.caib.seycon.ng.comu.RolGrant;
import es.caib.seycon.ng.comu.SoffidObjectTrigger;
import es.caib.seycon.ng.comu.SoffidObjectType;
import es.caib.seycon.ng.comu.Usuari;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.exception.UnknownRoleException;
import es.caib.seycon.ng.exception.UnknownUserException;
import es.caib.seycon.ng.sync.agent.Agent;
import es.caib.seycon.ng.sync.engine.extobj.AccountExtensibleObject;
import es.caib.seycon.ng.sync.engine.extobj.AttributeReference;
import es.caib.seycon.ng.sync.engine.extobj.GrantExtensibleObject;
import es.caib.seycon.ng.sync.engine.extobj.GroupExtensibleObject;
import es.caib.seycon.ng.sync.engine.extobj.MemberAttributeReference;
import es.caib.seycon.ng.sync.engine.extobj.ObjectTranslator;
import es.caib.seycon.ng.sync.engine.extobj.RoleExtensibleObject;
import es.caib.seycon.ng.sync.engine.extobj.UserExtensibleObject;
import es.caib.seycon.ng.sync.engine.extobj.ValueObjectMapper;
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

public class AWSAgent extends Agent implements ExtensibleObjectMgr, UserMgr, ReconcileMgr2, GroupMgr, RoleMgr {

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
	 * @param params Parámetros de configuración:
	 *               <li>0 = código de usuario LDAP</li>
	 *               <li>1 = contraseña de acceso LDAP</li>
	 *               <li>2 = host</li>
	 *               <li>3 = Nombre del attribute password</li>
	 *               <li>4 = Algoritmo de hash</li>
	 */
	public AWSAgent() throws RemoteException {
	}

	@Override
	public void init() throws InternalErrorException {
		log.info("Starting AWS agent on {}", getDispatcher().getCodi(), null);

		credentials = new BasicAWSCredentials(getDispatcher().getParam0(),
				Password.decode(getDispatcher().getParam1()).getPassword());

		log.info("Key   : " + getDispatcher().getParam0());
		log.info("Secret: " + getDispatcher().getParam1());
		clientConfig = new ClientConfiguration();
		debugEnabled = "true".equals(getDispatcher().getParam2());
	}

	/************* PRIMITIVE AWS ACTIONS 
	 * @throws InternalErrorException ***************************/
	private void updateGroupObject(ExtensibleObject src, ExtensibleObject obj) throws InternalErrorException {
		AmazonIdentityManagementClient client = getAmazonClient();
		String groupName = vom.toSingleString(obj.getAttribute("groupName"));
		try {
			GetGroupResult resp = client.getGroup(new GetGroupRequest(groupName));

			Group awsGroup = resp.getGroup();
			
			ExtensibleObject currentObject = generateExtensibleObject(obj.getObjectType(), awsGroup);
			if (preUpdate(src, obj, currentObject))
			{
				awsGroup.setPath(vom.toSingleString(obj.getAttribute("path")));
				UpdateGroupRequest req = new UpdateGroupRequest(groupName);
				req.setNewPath(vom.toSingleString(obj.getAttribute("path")));
				client.updateGroup(req);
				postUpdate(src, obj, currentObject);
			}
		} catch (NoSuchEntityException e) {
			if (preInsert(src, obj))
			{
				CreateGroupRequest createGroupRequest = new CreateGroupRequest();
				createGroupRequest.setGroupName(groupName);
				createGroupRequest.setPath(vom.toSingleString(obj.getAttribute("path")));
				client.createGroup(createGroupRequest);
				postInsert(src, obj, obj);
			}
		}
	}

	private AmazonIdentityManagementClient getAmazonClient() {
		AmazonIdentityManagementClient client = new AmazonIdentityManagementClient(credentials);
		client.setEndpoint("https://iam.amazonaws.com");

		return client;

	}

	private void removeGroupObject(ExtensibleObject src, ExtensibleObject obj) throws InternalErrorException {
		AmazonIdentityManagementClient client = getAmazonClient();
		String groupName = vom.toSingleString(obj.getAttribute("groupName"));
		try {
			GetGroupResult resp = client.getGroup(new GetGroupRequest(groupName));

			Group awsGroup = resp.getGroup();
			if (awsGroup != null)
			{
				ExtensibleObject currentEntry = generateExtensibleObject(obj.getObjectType(), awsGroup);
				if (preDelete(src, currentEntry))
				{
					awsGroup.setPath(vom.toSingleString(obj.getAttribute("path")));
					client.deleteGroup(new DeleteGroupRequest(groupName));
					postDelete(src, currentEntry);
				}
			}
		} catch (NoSuchEntityException e) {
		}
	}

	private void updateUserObject(ExtensibleObject src, ExtensibleObject obj, boolean setPassword) throws InternalErrorException {
		AmazonIdentityManagementClient client = getAmazonClient();
		String userName = vom.toSingleString(obj.getAttribute("userName"));
		// Update or cretae user
		try {
			GetUserRequest r = new GetUserRequest();
			r.setUserName(userName);
			GetUserResult resp = client.getUser(r);
			ExtensibleObject currentObject = generateExtensibleObject(obj.getObjectType(), resp.getUser());
			if (preUpdate(src, obj, currentObject))
			{
				UpdateUserRequest r2 = new UpdateUserRequest(userName);
				r2.setNewPath(vom.toSingleString(obj.getAttribute("path")));
				client.updateUser(r2);
				postUpdate(src, obj, currentObject);
			}
		} catch (NoSuchEntityException e) {
			if (preInsert(src, obj))
			{
				CreateUserRequest createUserRequest = new CreateUserRequest();
				createUserRequest.setUserName(userName);
				createUserRequest.setPath(vom.toSingleString(obj.getAttribute("path")));
				client.createUser(createUserRequest);
				setPassword = true;
			}
		}
		if (setPassword && obj.containsKey("password")) {
			try {
				log.info("Setting password");
				UpdateLoginProfileRequest clpr = new UpdateLoginProfileRequest(userName);
				clpr.setPassword(vom.toSingleString(obj.getAttribute("password")));
				if (obj.containsKey("mustChange"))
					clpr.setPasswordResetRequired(vom.toBoolean(obj.getAttribute("mustChange")));
				client.updateLoginProfile(clpr);
				log.info("Password set ");
			} catch (NoSuchEntityException e) {
				log.info("Creating password");
				CreateLoginProfileRequest clpr = new CreateLoginProfileRequest(userName,
						vom.toSingleString(obj.getAttribute("password")));
				if (obj.containsKey("mustChange"))
					clpr.setPasswordResetRequired(vom.toBoolean(obj.getAttribute("mustChange")));
				client.createLoginProfile(clpr);
				log.info("Password created");
			}
		}
	}

	private void updateUserObjectGroups(Account acc) throws InternalErrorException {
		AmazonIdentityManagementClient client = getAmazonClient();
		String accountName = acc.getName();
		ListGroupsForUserResult groups = client.listGroupsForUser(new ListGroupsForUserRequest(accountName));
		Collection<RolGrant> grants = getServer().getAccountRoles(acc.getName(), acc.getDispatcher());

		Set<String> groupsToAdd = new HashSet<String>();
		Set<String> groupsToRemove = new HashSet<String>();

		for (RolGrant grant : grants)
			groupsToAdd.add(grant.getRolName());
		for (Group g : groups.getGroups()) {
			groupsToRemove.add(g.getGroupName());
		}

		for (String groupToAdd : groupsToAdd) {
			if (groupsToRemove.contains(groupToAdd)) {
				log.info("Keeping group "+groupToAdd+" to "+accountName);
				groupsToRemove.remove(groupToAdd);
			} else {
				log.info("Adding group "+groupToAdd+" to "+accountName);
				if (runGrantTrigger(SoffidObjectTrigger.PRE_INSERT, groupToAdd, accountName, 
						true))
				{
					client.addUserToGroup(new AddUserToGroupRequest(groupToAdd, accountName));
					runGrantTrigger(SoffidObjectTrigger.POST_INSERT, groupToAdd, accountName, 
							true);
				}
			}
		}

		for (String groupToRemove : groupsToRemove) {
			log.info("Removing group "+groupToRemove+" from "+accountName);
			if (runGrantTrigger(SoffidObjectTrigger.PRE_DELETE, groupToRemove, accountName, 
					false))
			{
				client.removeUserFromGroup(new RemoveUserFromGroupRequest(groupToRemove, accountName));
				runGrantTrigger(SoffidObjectTrigger.PRE_DELETE, groupToRemove, accountName, 
						false);
			}
		}

	}

	private void removeUserObject(ExtensibleObject src, ExtensibleObject obj) throws InternalErrorException {
		AmazonIdentityManagementClient client = getAmazonClient();
		String userName = vom.toSingleString(obj.getAttribute("userName"));
		// 1. Remove login profile
		if (preDelete(src, obj)) {
			try {
				DeleteLoginProfileRequest req = new DeleteLoginProfileRequest(userName);
				client.deleteLoginProfile(req);
				ListAccessKeysRequest listAccessKeysRequest = new ListAccessKeysRequest();
				listAccessKeysRequest.setUserName(userName);
				ListAccessKeysResult r;
				do
				{
					r = client.listAccessKeys(listAccessKeysRequest );
					for ( AccessKeyMetadata q: r.getAccessKeyMetadata() )
					{
						DeleteAccessKeyRequest req2 = new DeleteAccessKeyRequest(userName, q.getAccessKeyId());
						client.deleteAccessKey(req2);
					}
					
				} while (r.isTruncated());
			} catch (NoSuchEntityException e) {
				// Login profile does not exist
			}
			// 2. Remove user
			try {
				client.deleteUser(new DeleteUserRequest(userName));
			} catch (NoSuchEntityException e) {
				// User does not exist
			}
			postDelete(src, obj);
		}
	}

	private void disableUserObject(ExtensibleObject src, ExtensibleObject obj) throws InternalErrorException {
		AmazonIdentityManagementClient client = getAmazonClient();
		
		if (preDelete(src, obj))
		{
			String userName = vom.toSingleString(obj.getAttribute("userName"));
			debugObject("Removing user "+userName, obj, "");
			// 1. Remove login profile
				log.info("Deleting login profile");
				try {
				DeleteLoginProfileRequest req = new DeleteLoginProfileRequest(userName);
				client.deleteLoginProfile(req);
			} catch (NoSuchEntityException e) {
				// Login profile does not exist
			}
			ListAccessKeysRequest listAccessKeysRequest = new ListAccessKeysRequest();
			listAccessKeysRequest.setUserName(userName);
			ListAccessKeysResult r;
			do
			{
				log.info("Getting access keys");
				r = client.listAccessKeys(listAccessKeysRequest );
				log.info("Got keys " +r);
				for ( AccessKeyMetadata q: r.getAccessKeyMetadata() )
				{
					log.info("Deleting access key "+q.getAccessKeyId());
					DeleteAccessKeyRequest req2 = new DeleteAccessKeyRequest(userName, q.getAccessKeyId());
					client.deleteAccessKey(req2);
				}
				
			} while (r.isTruncated());
			postDelete(src, obj);
		}
	}

	public void removeRole(String name, String system) throws RemoteException, InternalErrorException {
		Rol rol = new Rol();
		rol.setNom(name);
		if (getCodi().equals(system)) {
			rol.setBaseDeDades(system);

			ExtensibleObject roleObject = new RoleExtensibleObject(rol, getServer());
			try {
				for (ExtensibleObjectMapping eom : objectMappings) {
					if (eom.getSoffidObject().equals(SoffidObjectType.OBJECT_ROLE)) {
						if (!"true".equals(eom.getProperties().get("preventDeletion"))) {
							String condition = eom.getCondition();
							eom.setCondition(null);
							try {
								ExtensibleObject obj = objectTranslator.generateObject(roleObject, eom);
								if (obj != null)
									removeGroupObject(roleObject, obj);
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

	public void updateRole(Rol rol) throws RemoteException, InternalErrorException {
		if (rol.getBaseDeDades().equals(getDispatcher().getCodi())) {
			try {
				RoleExtensibleObject sourceObject = new RoleExtensibleObject(rol, getServer());
				debugObject("Updating role", sourceObject, "");

				for (ExtensibleObjectMapping mapping : objectMappings) {
					if (mapping.getSoffidObject().equals(SoffidObjectType.OBJECT_ROLE)) {
						if (objectTranslator.evalCondition(sourceObject, mapping)) {
							ExtensibleObject obj = objectTranslator.generateObject(sourceObject, mapping);
							if (obj != null)
								updateGroupObject(sourceObject, obj);
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

	public void removeGroup(String name) throws RemoteException, InternalErrorException {
		Grup grup = new Grup();
		grup.setCodi(name);
		GroupExtensibleObject groupObject = new GroupExtensibleObject(grup, getDispatcher().getCodi(), getServer());
		try {
			for (ExtensibleObjectMapping eom : objectMappings) {
				if (!"true".equals(eom.getProperties().get("preventDeletion"))) {
					String condition = eom.getCondition();
					eom.setCondition(null);
					try {
						ExtensibleObject obj = objectTranslator.generateObject(groupObject, eom);
						if (obj != null)
							removeGroupObject(groupObject, obj);
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

	public void updateGroup(String name, Grup group) throws RemoteException, InternalErrorException {

		try {
			GroupExtensibleObject sourceObject = new GroupExtensibleObject(group, getCodi(), getServer());
			for (ExtensibleObjectMapping mapping : objectMappings) {
				if (mapping.getSoffidObject().equals(SoffidObjectType.OBJECT_GROUP)) {
					if (objectTranslator.evalCondition(sourceObject, mapping)) {
						ExtensibleObject obj = objectTranslator.generateObject(sourceObject, mapping);
						if (obj != null)
							updateGroupObject(sourceObject, obj);
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

	public List<RolGrant> getAccountGrants(String accountName) throws RemoteException, InternalErrorException {
		log.info("Getting roles for "+accountName);
		AmazonIdentityManagementClient client = getAmazonClient();
		String userName = vom.toSingleString(accountName);
		ListGroupsForUserResult groups = client.listGroupsForUser(new ListGroupsForUserRequest(accountName));

		List<RolGrant> grants = new LinkedList<RolGrant>();

		for (Group g : groups.getGroups()) {
			log.info("> Found group "+g.getGroupName());
			RolGrant rg = new RolGrant();
			rg.setDispatcher(getCodi());
			rg.setOwnerAccountName(accountName);
			rg.setOwnerDispatcher(accountName);
			rg.setRolName(g.getGroupName());
			grants.add(rg);
		}
		return grants;
	}

	public Account getAccountInfo(String accountName) throws RemoteException, InternalErrorException {
		AmazonIdentityManagementClient client = getAmazonClient();
		for (ExtensibleObjectMapping mapping : objectMappings) {
			if (mapping.getSoffidObject().equals(SoffidObjectType.OBJECT_ACCOUNT)) {
				GetUserRequest req = new GetUserRequest();
				req.setUserName(accountName);
				try {
					GetUserResult resp = client.getUser(req);
					ExtensibleObject eo = new ExtensibleObject();
					eo.setObjectType(mapping.getSystemObject());
					eo.setAttribute("userName", resp.getUser().getUserName());
					eo.setAttribute("arn", resp.getUser().getArn());
					eo.setAttribute("createDate", resp.getUser().getCreateDate());
					eo.setAttribute("passwordLastUsed", resp.getUser().getPasswordLastUsed());
					eo.setAttribute("path", resp.getUser().getPath());
					eo.setAttribute("userId", resp.getUser().getUserId());
					debugObject("Parsed object", eo, "  ");
					Account acc = vom.parseAccount(objectTranslator.parseInputObject(eo, mapping));
					if (debugEnabled)
						log.info("Resulting account: " + acc.toString());
					if (acc != null)
						return acc;
				} catch (NoSuchEntityException e) {
					log.info("Unable to get " + accountName + " account");
				}
			}
		}
		return null;
	}

	public List<String> getAccountsList() throws RemoteException, InternalErrorException {
		AmazonIdentityManagementClient client = getAmazonClient();
		ListUsersResult users = client.listUsers();

		List<String> accounts = new LinkedList<String>();

		log.info("Getting accounts list");
		for (User u : users.getUsers()) {
			log.info("Got account "+u.getUserName()+" "+u.toString());
			accounts.add(u.getUserName());
		}
		return accounts;
	}

	public Rol getRoleFullInfo(String roleName) throws RemoteException, InternalErrorException {
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
					eo.setAttribute("createDate", resp.getGroup().getCreateDate());
					eo.setAttribute("path", resp.getGroup().getPath());
					eo.setAttribute("groupId", resp.getGroup().getGroupId());
					debugObject("Parsed object", eo, "  ");
					ExtensibleObject eso = objectTranslator.parseInputObject(eo, mapping);
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

	public List<String> getRolesList() throws RemoteException, InternalErrorException {
		AmazonIdentityManagementClient client = getAmazonClient();
		ListGroupsResult users = client.listGroups();

		List<String> roleNames = new LinkedList<String>();

		log.info("Getting roles list");
		for (Group g : users.getGroups()) {
			log.info("Got "+g.getGroupName());
			roleNames.add(g.getGroupName());
		}
		return roleNames;
	}

	public void removeUser(String accountName) throws RemoteException, InternalErrorException {
		Account acc = getServer().getAccountInfo(accountName, getCodi());
		if (acc == null) {
			removeScimUser(accountName);
		} else if (acc.isDisabled()) {
			disableScimUser(acc);
		} else {
			try {
				Usuari u = getServer().getUserInfo(accountName, getCodi());
				updateUser(acc, u);
			} catch (UnknownUserException e) {
				updateUser(acc);
			}
		}
	}

	public void removeScimUser(String accountName) throws RemoteException, InternalErrorException {
		Account acc = new Account();
		acc.setName(accountName);
		acc.setDispatcher(getCodi());
		ExtensibleObject userObject = new AccountExtensibleObject(acc, getServer());
		try {
			for (ExtensibleObjectMapping eom : objectMappings) {
				if (!"true".equals(eom.getProperties().get("preventDeletion"))) {
					String condition = eom.getCondition();
					eom.setCondition(null);
					try {
						ExtensibleObject obj = objectTranslator.generateObject(userObject, eom);
						if (obj != null)
							removeUserObject(userObject, obj);
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

	public void disableScimUser(Account acc) throws RemoteException, InternalErrorException {
		try {
			Usuari u = null;
			ExtensibleObject o = null;
			try {
				u = getServer().getUserInfo(acc.getName(), acc.getDispatcher());
				o = new UserExtensibleObject(acc, u, getServer());
			} catch (UnknownUserException e) {
				o = new AccountExtensibleObject(acc, getServer());
			}
			for (ExtensibleObjectMapping eom : objectMappings) {
				if (eom.getSoffidObject().toString().equals(o.getObjectType()) && !"true".equals(eom.getProperties().get("preventDeletion"))) {
					String condition = eom.getCondition();
					eom.setCondition(null);
					try {
						ExtensibleObject obj = objectTranslator.generateObject(o, eom);
						if (obj != null)
						{
							disableUserObject(o, obj);
							return;
						}
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

	public void updateUser(Account acc, Usuari user) throws RemoteException, InternalErrorException {
		ExtensibleObject sourceObject = new UserExtensibleObject(acc, user, getServer());
		log.info("Updating account "+acc.getName());
		try {
			for (ExtensibleObjectMapping mapping : objectMappings) {
				if (mapping.getSoffidObject().equals(SoffidObjectType.OBJECT_USER)) {
					if (objectTranslator.evalCondition(sourceObject, mapping)) {
						ExtensibleObject obj = objectTranslator.generateObject(sourceObject, mapping);
						Password password = getServer().getOrGenerateUserPassword(acc.getName(), getCodi());
						obj.setAttribute("password", password.getPassword());
						obj.setAttribute("mustChange", Boolean.FALSE);
						if (obj != null)
							updateUserObject(sourceObject, obj, true);
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

		ExtensibleObject sourceObject = new AccountExtensibleObject(acc, getServer());
		try {
			for (ExtensibleObjectMapping mapping : objectMappings) {
				if (mapping.getSoffidObject().equals(SoffidObjectType.OBJECT_ACCOUNT)) {
					if (objectTranslator.evalCondition(sourceObject, mapping)) {
						ExtensibleObject obj = objectTranslator.generateObject(sourceObject, mapping);
						if (obj != null) {
							obj.setAttribute("password",
									getServer().getOrGenerateUserPassword(acc.getName(), getCodi()));
							obj.setAttribute("mustChange", Boolean.FALSE);
							updateUserObject(sourceObject, obj, false);
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

	public void updateUserPassword(String accountName, Usuari user, Password password, boolean mustChange)
			throws RemoteException, InternalErrorException {
		Account acc = new Account();
		acc.setName(accountName);
		if (user != null)
			acc.setDescription(user.getFullName());
		acc.setDispatcher(getCodi());
		ExtensibleObject object = user == null ? new AccountExtensibleObject(acc, getServer())
				: new UserExtensibleObject(acc, user, getServer());
		ExtensibleObjects objects = objectTranslator.generateObjects(object);
		try {
			for (ExtensibleObject object2 : objects.getObjects()) {
				object2.setAttribute("password", password.getPassword());
				object2.setAttribute("mustChange", mustChange);
				updateUserObject(object, object2, true);
			}
			updateUserObjectGroups(acc);
		} catch (Exception e) {
			throw new InternalErrorException(e.getMessage(), e);
		}
	}

	public boolean validateUserPassword(String arg0, Password arg1) throws RemoteException, InternalErrorException {
		return false;
	}

	public void configureMappings(Collection<ExtensibleObjectMapping> mapping)
			throws RemoteException, InternalErrorException {
		this.objectMappings = mapping;
		this.objectTranslator = new ObjectTranslator(getDispatcher(), getServer(), mapping);
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
					debugObject(null, subObj2, indent + "   ", "" + (i++) + ": ");
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
	 * Actualizar los datos del usuario. Crea el usuario en la base de datos y le
	 * asigna una contraseña aleatoria. <BR>
	 * Da de alta los roles<BR>
	 * Le asigna los roles oportuno.<BR>
	 * Le retira los no necesarios.
	 * 
	 * @param user código de usuario
	 * @throws                        java.rmi.RemoteException error de
	 *                                comunicaciones con el servidor
	 * @throws InternalErrorException cualquier otro problema
	 */
	public void updateUser(String account, Usuari usu)
			throws java.rmi.RemoteException, es.caib.seycon.ng.exception.InternalErrorException {
		Account acc = getServer().getAccountInfo(account, getCodi());
		updateUser(acc, usu);
	}

	public void updateUser(String account, String descripcio)
			throws RemoteException, es.caib.seycon.ng.exception.InternalErrorException {
		Account acc = getServer().getAccountInfo(account, getCodi());
		if (acc == null)
			removeScimUser(account);
		else
			updateUser(acc);

	}

	public ExtensibleObject getNativeObject(SoffidObjectType type, String object1, String object2)
			throws RemoteException, InternalErrorException {
		ExtensibleObject sourceObject = getExtensibleObject(type, object1, object2);
		debugObject("Object to find", sourceObject, "  ");

		ExtensibleObjects targetObjects = new ExtensibleObjects();
		for (ExtensibleObjectMapping mapping: objectMappings)
		{
			ExtensibleObject to = objectTranslator.generateObject(sourceObject, mapping,  true);
			if (to != null && mapping.getSoffidObject().equals(type))
			{
				if ( type == SoffidObjectType.OBJECT_GROUP || type == SoffidObjectType.OBJECT_ROLE)
				{
					AmazonIdentityManagementClient client = getAmazonClient();
					String groupName = vom.toSingleString(to.getAttribute("groupName"));
					try {
						GetGroupResult resp = client.getGroup(new GetGroupRequest(groupName));

						Group awsGroup = resp.getGroup();
						ExtensibleObject eo = generateExtensibleObject( mapping.getSystemObject(), awsGroup);
						return eo;
					} catch (NoSuchEntityException e) {
					}

				} else if ( type == SoffidObjectType.OBJECT_ACCOUNT || type == SoffidObjectType.OBJECT_USER)
				{
					AmazonIdentityManagementClient client = getAmazonClient();
					debugObject("Object to read", to, "  ");
					String userName = vom.toSingleString(to.getAttribute("userName"));
					try {
						GetUserRequest r = new GetUserRequest();
						r.setUserName(userName);
						GetUserResult resp = client.getUser(r);
						ExtensibleObject eo = generateExtensibleObject( mapping.getSystemObject(), resp.getUser());
						ListGroupsForUserResult groups = client.listGroupsForUser(new ListGroupsForUserRequest(userName));
						int i = 0;
						for ( Group group: groups.getGroups())
						{
							Map<String, Object> group2 = new HashMap<String, Object>();
							fillAttributes(group2 , group, 0);
							eo.put("groups["+i+"]", group2);
							i++;
						}
						return eo;
					} catch (NoSuchEntityException e) {
					}

				}
			}
		}
		return null;
	}

	public ExtensibleObject generateExtensibleObject(String objectType, Object awsGroup) {
		ExtensibleObject eo = new ExtensibleObject ();
		eo.setObjectType(objectType);
		fillAttributes (eo, awsGroup, 0);
		return eo;
	}

	private void fillAttributes(Map<String,Object> eo, Object bean, int depth) 
	{
		try {
			Map<String,Object> properties = PropertyUtils.describe(bean);
			for (String property: properties.keySet() )
			{
				if (PropertyUtils.isWriteable(bean, property))
				{
					System.out.println("Filling property "+property);
					Object value = PropertyUtils.getProperty(bean, property);
					if (value == null ||
							value instanceof String ||
							value instanceof Date ||
							value instanceof Calendar ||
							value instanceof Integer ||
							value instanceof Long ||
							value instanceof Boolean)
					{
						eo.put(property, value);
					}
					else if (depth < 3 )
				    
					{
						HashMap<String,Object> r = new HashMap<String, Object>();
						eo.put(property, r);
						fillAttributes(r, value, depth + 1 );
					}
				}
			}
		} catch (Exception e) {}
	}

	public ExtensibleObject getSoffidObject(SoffidObjectType type, String object1, String object2)
			throws RemoteException, InternalErrorException {
		try {
			ExtensibleObject s = getNativeObject(type, object1, object2);
			if (s != null)
			{
				for (ExtensibleObject so: objectTranslator.parseInputObjects(s).getObjects())
				{
					return so;
				}
			}

			return null;
		} catch (InternalErrorException e) {
			throw e;
		} catch (Exception e) {
			throw new InternalErrorException("Error retrieving object information", e);
		}
	}

	protected boolean runTrigger (SoffidObjectTrigger triggerType,
			ExtensibleObject soffidObject,
			ExtensibleObject adObject,
			ExtensibleObject currentEntry) throws InternalErrorException
	{
		SoffidObjectType sot = SoffidObjectType.fromString(soffidObject.getObjectType());
		for ( ExtensibleObjectMapping eom : objectTranslator.getObjectsBySoffidType(sot))
		{
			if (adObject == null || adObject.getObjectType().equals(eom.getSystemObject()))
			{
				for ( ObjectMappingTrigger trigger: eom.getTriggers())
				{
					if (trigger.getTrigger().equals (triggerType))
					{
						ExtensibleObject eo = new ExtensibleObject();
						eo.setAttribute("source", soffidObject);
						eo.setAttribute("newObject", adObject);
						eo.setAttribute("oldObject", currentEntry);
						if ( ! objectTranslator.evalExpression(eo, trigger.getScript()) )
						{
							log.info("Trigger "+triggerType+" returned false");
							if (debugEnabled)
							{
								if (currentEntry != null)
									debugObject("old object", currentEntry, "  ");
								if (adObject != null)
									debugObject("new object", adObject, "  ");
							}
							return false;
						}
					}
				}
			}
		}
		return true;
		
	}

	protected boolean runGrantTrigger (SoffidObjectTrigger triggerType,
			String group, String user, boolean add) throws InternalErrorException
	{
		for ( ExtensibleObjectMapping eom : objectTranslator.getObjects())
		{
			if (eom.getSoffidObject().equals (SoffidObjectType.OBJECT_GRANT) ||
				eom.getSoffidObject().equals (SoffidObjectType.OBJECT_GRANTED_GROUP) ||
				eom.getSoffidObject().equals (SoffidObjectType.OBJECT_GRANTED_ROLE) ||
				eom.getSoffidObject().equals (SoffidObjectType.OBJECT_ALL_GRANTED_GROUP) ||
				eom.getSoffidObject().equals (SoffidObjectType.OBJECT_ALL_GRANTED_ROLES))
			{
				for ( ObjectMappingTrigger trigger: eom.getTriggers())
				{
					if (trigger.getTrigger().equals (triggerType))
					{

						RolGrant rg = new RolGrant();
						rg.setRolName(group);
						rg.setOwnerAccountName(user);
						rg.setOwnerDispatcher(getCodi());
						rg.setDispatcher(getCodi());
						try
						{
							Rol ri = getServer().getRoleInfo(group, getDispatcher().getCodi());
							if (ri != null)
							{
								rg.setIdRol(ri.getId());
								rg.setInformationSystem(ri.getCodiAplicacio());
								// Ignore group only grants
								if (eom.getSoffidObject().equals (SoffidObjectType.OBJECT_GRANTED_GROUP) ||
										eom.getSoffidObject().equals (SoffidObjectType.OBJECT_ALL_GRANTED_GROUP) )
									continue;
							} else {
								// Ignore role only grants
								if (eom.getSoffidObject().equals (SoffidObjectType.OBJECT_GRANTED_ROLE) ||
										eom.getSoffidObject().equals (SoffidObjectType.OBJECT_ALL_GRANTED_ROLES) )
									continue;
							}
						} catch (UnknownRoleException e) 
						{
							// Ignore role only grants
							if (eom.getSoffidObject().equals (SoffidObjectType.OBJECT_GRANTED_ROLE) ||
									eom.getSoffidObject().equals (SoffidObjectType.OBJECT_ALL_GRANTED_ROLES) )
								continue;
						}
						ExtensibleObject soffidObject = new GrantExtensibleObject(rg, getServer());
						
						ExtensibleObject eo = new ExtensibleObject();
						eo.setAttribute("source", soffidObject);
						ExtensibleObject eo2 = new ExtensibleObject();
						eo.setAttribute( add ? "newObject": "oldObject", eo2);
						if ( ! objectTranslator.evalExpression(eo, trigger.getScript()) )
						{
							log.info("Trigger "+triggerType+" returned false");
							return false;
						}
					}
				}
			}
		}
		return true;
		
	}

	protected boolean preUpdate(ExtensibleObject soffidObject,
			ExtensibleObject adObject, ExtensibleObject currentEntry)
			throws InternalErrorException {
		return runTrigger(SoffidObjectTrigger.PRE_UPDATE, soffidObject, adObject, currentEntry);
	}

	protected boolean preInsert(ExtensibleObject soffidObject,
			ExtensibleObject adObject) throws InternalErrorException {
		return runTrigger(SoffidObjectTrigger.PRE_INSERT, soffidObject, adObject, null);
	}

	protected boolean preDelete(ExtensibleObject soffidObject,
			ExtensibleObject currentEntry) throws InternalErrorException {
		return runTrigger(SoffidObjectTrigger.PRE_DELETE, soffidObject, null, currentEntry);
	}

	protected boolean postUpdate(ExtensibleObject soffidObject,
			ExtensibleObject adObject, ExtensibleObject currentEntry)
			throws InternalErrorException {
		return runTrigger(SoffidObjectTrigger.POST_UPDATE, soffidObject, adObject, currentEntry);
	}

	protected boolean postInsert(ExtensibleObject soffidObject,
			ExtensibleObject adObject, ExtensibleObject currentEntry)
			throws InternalErrorException {
		return runTrigger(SoffidObjectTrigger.POST_INSERT, soffidObject, adObject, currentEntry);
	}

	protected boolean postDelete(ExtensibleObject soffidObject,
			ExtensibleObject currentEntry) throws InternalErrorException {
		return runTrigger(SoffidObjectTrigger.POST_DELETE, soffidObject,  null, currentEntry);
	}


}
