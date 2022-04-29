/****************************** File Header ******************************\
File Name:    AdobeCSExtension.cs
Project:      AdobeCSExtension
Author:       Pedro Rivas
Email:        admin@rivas.pw

This project will create a dynamic library extension that will allow MIM
(Microsoft Identity Manager) to connect to the Adobe Management Console.

THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, 
EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED 
WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.
\***************************************************************************/

using System;
using System.IO;
using System.Text;
using System.Collections.ObjectModel;
using System.Collections.Generic;
using Microsoft.MetadirectoryServices;
using System.Security.Cryptography.X509Certificates;
using Newtonsoft.Json.Linq;
using System.Net.Http;
using System.Threading;
using Jose;
using RestSharp;
using System.Net;

namespace FimSync_Ezma
{
    public class EzmaExtension :
    IMAExtensible2CallExport,
    IMAExtensible2CallImport,
    IMAExtensible2GetSchema,
    IMAExtensible2GetCapabilities,
    IMAExtensible2GetParameters
    {
        //
        // Constructor
        //
        public EzmaExtension()
        {
            //
            // TODO: Add constructor logic here
            //
        }

        private int m_importPageSize = 2500;
        private int m_importDefaultPageSize = 2500;
        private int m_importMaxPageSize = 2500;
        private int m_exportDefaultPageSize = 50;
        private int m_exportMaxPageSize = 1000;

        log4net.ILog log;

        private JObject JWTToken;
        private string clientID;
        private string orgID;
        private string adobeIdentityMgmtSvc;
        private int userPage;
        private int groupPage;
        private int userGroupPage;
        private bool moreUsers = true;
        private bool moreGroups = true;
        public bool groupHasUsers = true;

        OperationType m_importOperation;

        public MACapabilities Capabilities
        {
            get
            {
                MACapabilities myCapabilities = new MACapabilities();
                myCapabilities.ConcurrentOperation = false;
                myCapabilities.ObjectRename = true;
                myCapabilities.DeleteAddAsReplace = true;
                myCapabilities.DeltaImport = false;
                myCapabilities.DistinguishedNameStyle = MADistinguishedNameStyle.Generic;
                myCapabilities.ExportType = MAExportType.AttributeUpdate;
                myCapabilities.NoReferenceValuesInFirstExport = true;
                myCapabilities.Normalizations = MANormalizations.None;
                return myCapabilities;
            }
        }

        public IList<ConfigParameterDefinition> GetConfigParameters(KeyedCollection<string, ConfigParameter> configParameters, ConfigParameterPage page)
        {
            List<ConfigParameterDefinition> configParametersDefinitions = new List<ConfigParameterDefinition>();

            switch (page)
            {
                // Connectivity parameters.
                case ConfigParameterPage.Connectivity:
                    configParametersDefinitions.Add(ConfigParameterDefinition.CreateStringParameter("Adobe Identity Management Service", "", "https://ims-na1.adobelogin.com/ims/exchange/jwt/"));
                    configParametersDefinitions.Add(ConfigParameterDefinition.CreateStringParameter("Client ID", "", ""));
                    configParametersDefinitions.Add(ConfigParameterDefinition.CreateStringParameter("Client Secret", "", ""));
                    configParametersDefinitions.Add(ConfigParameterDefinition.CreateStringParameter("Subject", "", ""));
                    configParametersDefinitions.Add(ConfigParameterDefinition.CreateStringParameter("Organization ID", "", ""));
                    configParametersDefinitions.Add(ConfigParameterDefinition.CreateStringParameter("JWT Expiration Time (seconds)", "", "600"));
                    configParametersDefinitions.Add(ConfigParameterDefinition.CreateStringParameter(
                        ".P12 Location", 
                        "", 
                        "C:\\Program Files\\Microsoft Forefront Identity Manager\\2010\\Synchronization Service\\Extensions\\adobe-cert.p12"
                        ));
                    break;
                // Global parameters.
                case ConfigParameterPage.Global:
                    break;
                case ConfigParameterPage.Partition:
                    break;
                case ConfigParameterPage.RunStep:
                    break;
            }
            return configParametersDefinitions;
        }

        public ParameterValidationResult ValidateConfigParameters(KeyedCollection<string, ConfigParameter> configParameters, ConfigParameterPage page)
        {
            ParameterValidationResult myResults = new ParameterValidationResult();
            return myResults;
        }

        public Schema GetSchema(KeyedCollection<string, ConfigParameter> configParameters)
        {
            // Adobe schema
            SchemaType userType = SchemaType.Create("user", false);
            userType.Attributes.Add(SchemaAttribute.CreateSingleValuedAttribute("username", AttributeType.String));
            userType.Attributes.Add(SchemaAttribute.CreateSingleValuedAttribute("email", AttributeType.String));
            userType.Attributes.Add(SchemaAttribute.CreateSingleValuedAttribute("employeeID", AttributeType.String));
            userType.Attributes.Add(SchemaAttribute.CreateSingleValuedAttribute("firstname", AttributeType.String));
            userType.Attributes.Add(SchemaAttribute.CreateSingleValuedAttribute("lastname", AttributeType.String));
            userType.Attributes.Add(SchemaAttribute.CreateSingleValuedAttribute("domain", AttributeType.String));
            userType.Attributes.Add(SchemaAttribute.CreateSingleValuedAttribute("status", AttributeType.String));
            userType.Attributes.Add(SchemaAttribute.CreateSingleValuedAttribute("country", AttributeType.String));
            userType.Attributes.Add(SchemaAttribute.CreateSingleValuedAttribute("type", AttributeType.String));

            SchemaType groupType = SchemaType.Create("group", false);
            groupType.Attributes.Add(SchemaAttribute.CreateAnchorAttribute("type", AttributeType.String));
            groupType.Attributes.Add(SchemaAttribute.CreateMultiValuedAttribute("groupName", AttributeType.String));
            groupType.Attributes.Add(SchemaAttribute.CreateMultiValuedAttribute("member", AttributeType.String));
            groupType.Attributes.Add(SchemaAttribute.CreateSingleValuedAttribute("memberCount", AttributeType.Integer));
            groupType.Attributes.Add(SchemaAttribute.CreateSingleValuedAttribute("groupId", AttributeType.Integer));

            Schema schema = Schema.Create();
            schema.Types.Add(userType);
            schema.Types.Add(groupType);

            return schema;
        }

        public OpenImportConnectionResults OpenImportConnection(KeyedCollection<string, ConfigParameter> configParameters, Schema types, OpenImportConnectionRunStep importRunStep)
        {
            log = log4net.LogManager.GetLogger(System.Reflection.MethodBase.GetCurrentMethod().DeclaringType);
            FileInfo finfo = new FileInfo(Utils.ExtensionsDirectory + "\\log4netAdobeCS.config");
            log4net.Config.XmlConfigurator.ConfigureAndWatch(finfo);

            m_importOperation = importRunStep.ImportType;
            m_importPageSize = importRunStep.PageSize;

            log.Info("Import connection - start.");

            clientID = configParameters["Client ID"].Value;
            orgID = configParameters["Organization ID"].Value;
            adobeIdentityMgmtSvc = configParameters["Adobe Identity Management Service"].Value;

            string metascopes = "https://ims-na1.adobelogin.com/s/ent_user_sdk";

            Dictionary<object, object> payload = new Dictionary<object, object>();
            payload.Add("exp", DateTimeOffset.Now.ToUnixTimeSeconds() + 600);
            payload.Add("iss", orgID);
            payload.Add("sub", configParameters["Subject"].Value);
            payload.Add("aud", "https://ims-na1.adobelogin.com/c/" + clientID);
            string[] scopes = metascopes.Split(',');

            foreach (string scope in scopes)
            {
                payload.Add(scope, true);
            }

            X509Certificate2 cert = new X509Certificate2(configParameters[".P12 Location"].Value);

            string token = Jose.JWT.Encode(payload, cert.GetRSAPrivateKey(), JwsAlgorithm.RS256);

            //create request to Adobe to get token
            try
            {
                System.Net.ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;

                log.Info("Attempting to create a new JWT from Adobe.");

                var client = new RestClient(adobeIdentityMgmtSvc);

                var request = new RestRequest(Method.POST);
                request.AddHeader("cache-control", "no-cache");
                request.AddHeader("content-type", "multipart/form-data; boundary=----boundary");
                request.AddParameter("multipart/form-data; boundary=----boundary",
                    "------boundary\r\nContent-Disposition: form-data; name=\"client_id\"\r\n\r\n" + configParameters["Client ID"].Value +
                    "\r\n------boundary\r\nContent-Disposition: form-data; name=\"client_secret\"\r\n\r\n" + configParameters["Client Secret"].Value +
                    "\r\n------boundary\r\nContent-Disposition: form-data; name=\"jwt_token\"\r\n\r\n" + token +
                    "\r\n------boundary--", ParameterType.RequestBody);


                IRestResponse response = client.Execute(request);

                //parse Adobe response
                JWTToken = JObject.Parse(response.Content);
                
                log.Info("Successfully retrived and stored the JWT.");
            }
            catch (Exception e)
            {
                log.Info("Could not retrieve a new token from Adobe. Error: " + e.Message);
            }

            log.Info("Import connection - finish.");

            return new OpenImportConnectionResults();
        }

        public GetImportEntriesResults GetImportEntries(GetImportEntriesRunStep importRunStep)
        {
            log.Info("Import entries results - start");
            List<CSEntryChange> csentries = new List<CSEntryChange>();
            GetImportEntriesResults importReturnInfo = new GetImportEntriesResults();

            if (OperationType.Full == m_importOperation)
            {
                log.Info("Doing a full import operation.");

                var myHttpClient = new HttpClient();

                #region Get all users
                if (moreUsers)
                {
                    try
                    {
                        myHttpClient.DefaultRequestHeaders.Add("Authorization", "Bearer " + JWTToken["access_token"]);
                        myHttpClient.DefaultRequestHeaders.Add("X-Api-Key", clientID);

                        var responseAdobe = myHttpClient.GetAsync("https://usermanagement.adobe.io/v2/usermanagement/users/" + orgID + "/" + userPage);
                        var updateContents = responseAdobe.Result.Content.ReadAsStringAsync();
                        JObject userList = JObject.Parse(updateContents.Result);

                        foreach (JObject user in userList["users"])
                        {
                            CSEntryChange csentry = CSEntryChange.Create();
                            csentry.ObjectModificationType = ObjectModificationType.Add;
                            csentry.ObjectType = "user";

                            csentry.AttributeChanges.Add(AttributeChange.CreateAttributeAdd("username", Convert.ToString(user["username"])));
                            csentry.AttributeChanges.Add(AttributeChange.CreateAttributeAdd("firstname", Convert.ToString(user["firstname"])));
                            csentry.AttributeChanges.Add(AttributeChange.CreateAttributeAdd("lastname", Convert.ToString(user["lastname"])));
                            csentry.AttributeChanges.Add(AttributeChange.CreateAttributeAdd("email", Convert.ToString(user["email"]).ToLower()));
                            csentry.AttributeChanges.Add(AttributeChange.CreateAttributeAdd("domain", Convert.ToString(user["domain"])));
                            csentry.AttributeChanges.Add(AttributeChange.CreateAttributeAdd("status", Convert.ToString(user["status"])));
                            csentry.AttributeChanges.Add(AttributeChange.CreateAttributeAdd("country", Convert.ToString(user["country"])));
                            csentry.AttributeChanges.Add(AttributeChange.CreateAttributeAdd("type", Convert.ToString(user["type"])));

                            csentry.DN = Convert.ToString(user["username"]);

                            csentries.Add(csentry);
                        }

                        if (!(bool)userList["lastPage"])
                        {
                            moreUsers = true;
                            log.Info("JSON response is not the last page. More users to import exist.");
                            userPage++;

                            // Wait ten seconds to avoid the API call limit.
                            Thread.Sleep(10000);
                        }
                        else
                        {
                            moreUsers = false;
                            log.Info("JSON response is the last page. No more users to import.");
                            log.Info("Completed the full import operation.");
                        }

                    }
                    catch (Exception e)
                    {
                        log.Info("Error with getting Adobe users. Error: " + e.Message);
                    }
                }
                #endregion

                #region Get all groups
                if (moreGroups)
                {
                    try
                    {
                        var responseAdobe = myHttpClient.GetAsync("https://usermanagement.adobe.io/v2/usermanagement/groups/" + orgID + "/" + groupPage);
                        var updateContents = responseAdobe.Result.Content.ReadAsStringAsync();

                        JObject groupList = JObject.Parse(updateContents.Result);

                        foreach (JObject group in groupList["groups"])
                        {
                            log.Info("Found group " + group["groupName"]);
                            CSEntryChange csentry1 = CSEntryChange.Create();
                            csentry1.ObjectModificationType = ObjectModificationType.Add;
                            csentry1.ObjectType = "group";

                            csentry1.AttributeChanges.Add(AttributeChange.CreateAttributeAdd("type", group["type"].ToString()));
                            csentry1.AttributeChanges.Add(AttributeChange.CreateAttributeAdd("groupName", group["groupName"].ToString()));
                            csentry1.AttributeChanges.Add(AttributeChange.CreateAttributeAdd("memberCount", Convert.ToInt32(group["memberCount"].ToString())));
                            csentry1.AttributeChanges.Add(AttributeChange.CreateAttributeAdd("groupId", Convert.ToInt32(group["groupId"].ToString())));

                            csentry1.DN = group["groupName"].ToString();
                            log.Info("Retrieving group members for " + group["groupName"]);

                            IList<object> groupMembers = new List<object>();

                            userGroupPage = 0;
                            while (groupHasUsers)
                            {
                                responseAdobe = myHttpClient.GetAsync("https://usermanagement.adobe.io/v2/usermanagement/users/" + orgID + "/" + userGroupPage + "/" + group["groupName"].ToString());
                                updateContents = responseAdobe.Result.Content.ReadAsStringAsync();

                                JObject usersInGroup = JObject.Parse(updateContents.Result);

                                foreach (JObject user in usersInGroup["users"])
                                {
                                    groupMembers.Add(user["username"].ToString());
                                }

                                if ((bool)usersInGroup["lastPage"])
                                {
                                    groupHasUsers = false;
                                }
                                else
                                {
                                    userGroupPage++;
                                }

                                // Wait three seconds to avoid the API call limit. 
                                Thread.Sleep(3000);
                            }

                            groupHasUsers = true;

                            csentry1.AttributeChanges.Add(AttributeChange.CreateAttributeAdd("member", groupMembers));
                            csentries.Add(csentry1);
                        }

                        if (!(bool)groupList["lastPage"])
                        {
                            moreGroups = true;
                            log.Info("JSON response is not the last page. More groups to import exist.");
                            groupPage++;

                            // Wait three seconds to avoid the API call limit.
                            Thread.Sleep(3000);
                        }
                        else
                        {
                            moreGroups = false;
                            log.Info("JSON response is the last page. No more groups to import.");
                            log.Info("Completed the full import operation.");
                        }
                    }
                    catch (Exception e)
                    {
                        log.Info("Error with getting Adobe groups. Error: " + e.Message);
                    }
                }
                #endregion
            }

            if (OperationType.Delta == m_importOperation)
            {
                //Not implemented.
            }

            if (moreUsers || moreGroups)
            {
                importReturnInfo.MoreToImport = true;
            }
            else
            {
                importReturnInfo.MoreToImport = false;
            }

            importReturnInfo.CSEntries = csentries;
            log.Info("Import entries results - finish");

            return importReturnInfo;
        }

        public CloseImportConnectionResults CloseImportConnection(CloseImportConnectionRunStep importRunStepInfo)
        {
            return new CloseImportConnectionResults();
        }

        public void OpenExportConnection(KeyedCollection<string, ConfigParameter> configParameters, Microsoft.MetadirectoryServices.Schema types, OpenExportConnectionRunStep exportRunStep)
        {
            log = log4net.LogManager.GetLogger(System.Reflection.MethodBase.GetCurrentMethod().DeclaringType);
            FileInfo finfo = new FileInfo(Utils.ExtensionsDirectory + "\\log4netAdobeCS.config");
            log4net.Config.XmlConfigurator.ConfigureAndWatch(finfo);

            log.Info("Export connection - start.");

            System.Net.ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;

            clientID = configParameters["Client ID"].Value;
            orgID = configParameters["Organization ID"].Value;
            adobeIdentityMgmtSvc = configParameters["Adobe Identity Management Service"].Value;
            string metascopes = "https://ims-na1.adobelogin.com/s/ent_user_sdk";

            Dictionary<object, object> payload = new Dictionary<object, object>();
            payload.Add("exp", DateTimeOffset.Now.ToUnixTimeSeconds() + 600);
            payload.Add("iss", orgID);
            payload.Add("sub", configParameters["Subject"].Value);
            payload.Add("aud", "https://ims-na1.adobelogin.com/c/" + clientID);
            string[] scopes = metascopes.Split(',');

            foreach (string scope in scopes)
            {
                payload.Add(scope, true);
            }

            X509Certificate2 cert = new X509Certificate2(configParameters[".P12 Location"].Value);

            string token = Jose.JWT.Encode(payload, cert.GetRSAPrivateKey(), JwsAlgorithm.RS256);

            //create request to Adobe to get token
            try
            {
                log.Info("Attempting to create a new JWT from Adobe.");

                var client = new RestClient(adobeIdentityMgmtSvc);

                var request = new RestRequest(Method.POST);
                request.AddHeader("cache-control", "no-cache");
                request.AddHeader("content-type", "multipart/form-data; boundary=----boundary");
                request.AddParameter("multipart/form-data; boundary=----boundary",
                    "------boundary\r\nContent-Disposition: form-data; name=\"client_id\"\r\n\r\n" + configParameters["Client ID"].Value +
                    "\r\n------boundary\r\nContent-Disposition: form-data; name=\"client_secret\"\r\n\r\n" + configParameters["Client Secret"].Value +
                    "\r\n------boundary\r\nContent-Disposition: form-data; name=\"jwt_token\"\r\n\r\n" + token +
                    "\r\n------boundary--", ParameterType.RequestBody);

                IRestResponse response = client.Execute(request);

                //parse Adobe response
                JWTToken = JObject.Parse(response.Content);
                log.Info("Successfully retrived and stored the JWT.");
            }
            catch (Exception e)
            {
                log.Info("Could not retrieve a new token from Adobe. Error: " + e.Message);
            }

            log.Info("Export connection - finish.");
        }

        public PutExportEntriesResults PutExportEntries(IList<CSEntryChange> csentries)
        {
            //
            // The csentries parameter contains a collection of CSEntryChange
            // objects that need to be exported.  The number of CSEntryChange
            // objects is determined by the bacth size set on the Run Profile Step,
            // which contain be obtained from exportRunStep.BatchSize in OpenExportConnection().
            //

            PutExportEntriesResults exportEntriesResults = new PutExportEntriesResults();

            foreach (CSEntryChange csentryChange in csentries)
            {
                //Default is success.
                MAExportError exportResult = MAExportError.Success;
                List<AttributeChange> attributeChanges = new List<AttributeChange>();

                switch (csentryChange.ObjectModificationType)
                {
                    case ObjectModificationType.Add:
                        #region Create User
                        if (csentryChange.ObjectType == "user")
                        {
                            log.Info("Creating new user " + csentryChange.DN);

                            // Adobe JSON
                            JArray newAdobeUser = new JArray();
                            JObject user = new JObject();
                            JArray create = new JArray();
                            JObject createFederatedID = new JObject();
                            JObject createDetails = new JObject();

                            user["requestID"] = "action_1";
                            user["user"] = csentryChange.DN.Split('@')[0];
                            createDetails["option"] = "ignoreIfAlreadyExists";
                            createDetails["country"] = "US";

                            foreach (AttributeChange ch in csentryChange.AttributeChanges)
                            {
                                log.Info("Adding " + ch.Name + " " + ch.ValueChanges.Count + " " + ch.ValueChanges[0].Value.ToString());
                                switch (ch.Name)
                                {
                                    case "email":
                                        createDetails["email"] = ch.ValueChanges[0].Value.ToString();
                                        break;
                                    case "firstname":
                                        createDetails["firstname"] = ch.ValueChanges[0].Value.ToString();
                                        break;
                                    case "lastname":
                                        createDetails["lastname"] = ch.ValueChanges[0].Value.ToString();
                                        break;
                                    case "domain":
                                        user["domain"] = ch.ValueChanges[0].Value.ToString();
                                        break;
                                }
                            }

                            createFederatedID["createFederatedID"] = createDetails;
                            create.Add(createFederatedID);
                            user["do"] = create;
                            newAdobeUser.Add(user);

                            bool tooManyRequests = false;

                            do
                            {
                                try
                                {
                                    log.Info("Attempting to create user " + csentryChange.DN + ".");
                                    var myHttpClient = new HttpClient();

                                    myHttpClient.DefaultRequestHeaders.Add("Authorization", "Bearer " + JWTToken["access_token"]);
                                    myHttpClient.DefaultRequestHeaders.Add("X-Api-Key", clientID);

                                    var JSONContent = new StringContent(newAdobeUser.ToString(), Encoding.UTF8, "application/json");

                                    var responseAdobe = myHttpClient.PostAsync("https://usermanagement.adobe.io/v2/usermanagement/action/" + orgID, JSONContent);
                                    var updateContents = responseAdobe.Result.Content.ReadAsStringAsync();

                                    // 429 = too many requests... try again
                                    if (responseAdobe.Result.StatusCode.ToString().Equals("429"))
                                    {
                                        tooManyRequests = true;
                                        log.Info("Unable to create user: " + csentryChange.DN + ". Error: Too many requests!");
                                        Thread.Sleep(60000);
                                    }
                                    else if (responseAdobe.Result.StatusCode.ToString().Equals("OK"))
                                    {
                                        tooManyRequests = false;
                                        JObject adobeJob = JObject.Parse(updateContents.Result);
                                        if (adobeJob["result"].ToString().Equals("success"))
                                        {
                                            log.Info("Successfully created " + csentryChange.DN + ".");
                                        }
                                        else if (adobeJob["result"].ToString().Equals("error"))
                                        {
                                            log.Info("Unable to create user: " + csentryChange.DN + ". Error: " + adobeJob["errors"].ToString());
                                            exportResult = MAExportError.ExportErrorCustomContinueRun;
                                            exportEntriesResults.CSEntryChangeResults.Add(
                                                CSEntryChangeResult.Create(csentryChange.Identifier, attributeChanges, exportResult, "Adobe API Error", adobeJob["errors"].ToString()));
                                            continue;
                                        }
                                        else
                                        {
                                            log.Info("Unable to create user: " + csentryChange.DN + ". Error: " + adobeJob.ToString());
                                            exportResult = MAExportError.ExportErrorCustomContinueRun;
                                            exportEntriesResults.CSEntryChangeResults.Add(
                                                CSEntryChangeResult.Create(csentryChange.Identifier, attributeChanges, exportResult, "Adobe API Error", adobeJob.ToString()));
                                            continue;
                                        }
                                    }
                                    else
                                    {
                                        log.Info("Somethign else is up.. " + responseAdobe.Result.StatusCode);
                                    }
                                }
                                catch (Exception e)
                                {
                                    log.Info("Unable to create user: " + csentryChange.DN + ". Error: " + e.Message + ". StackTrace: " + e.StackTrace);
                                    exportResult = MAExportError.ExportErrorCustomContinueRun;
                                    exportEntriesResults.CSEntryChangeResults.Add(CSEntryChangeResult.Create(csentryChange.Identifier, attributeChanges, exportResult, "Unexpected error!", e.Message));
                                    continue;
                                }
                            } while (tooManyRequests);
                        }
                        #endregion
                        break;
                    case ObjectModificationType.Replace:
                    case ObjectModificationType.Update:
                        #region Update User
                        if (csentryChange.ObjectType == "user")
                        {
                            log.Info("Modifying " + csentryChange.DN + ".");

                            // Adobe JSON
                            JArray updateAdobeUser = new JArray();
                            JObject user = new JObject();
                            JArray doUpdate = new JArray();
                            JObject update = new JObject();
                            JObject updateDetails = new JObject();

                            user["user"] = csentryChange.DN.Split('@')[0];
                            user["requestID"] = "action_1";
                            user["domain"] = csentryChange.DN.Split('@')[1];
                            //updateDetails["option"] = "ignoreIfAlreadyExists";

                            foreach (AttributeChange ch in csentryChange.AttributeChanges)
                            {
                                //Loop that iterates the different attributes that are changing
                                foreach (ValueChange vch in ch.ValueChanges)
                                {
                                    //loop that iterates the different changes, this usually is an ADD plus a DELETE for
                                    //updating an attribute.
                                    switch (vch.ModificationType)
                                    {
                                        case ValueModificationType.Add:
                                            log.Info(String.Format("New value for {0} => {1}", ch.Name, vch.Value.ToString()));
                                            switch (ch.Name)
                                            {
                                                case "email":
                                                    updateDetails["email"] = vch.Value.ToString();
                                                    break;
                                                case "firstname":
                                                    updateDetails["firstname"] = vch.Value.ToString();
                                                    break;
                                                case "lastname":
                                                    updateDetails["lastname"] = vch.Value.ToString();
                                                    break;
                                            }
                                            break;
                                        case ValueModificationType.Delete:
                                            log.Info(String.Format("Old value for {0} => {1}", ch.Name, vch.Value.ToString()));
                                            break;
                                    }
                                }
                            }

                            update["update"] = updateDetails;
                            doUpdate.Add(update);
                            user["do"] = doUpdate;
                            updateAdobeUser.Add(user);

                            bool tooManyRequests = false;

                            do
                            {
                                try
                                {
                                    log.Info("Attempting to modify user " + csentryChange.DN + ".");
                                    var myHttpClient = new HttpClient();

                                    myHttpClient.DefaultRequestHeaders.Add("Authorization", "Bearer " + JWTToken["access_token"]);
                                    myHttpClient.DefaultRequestHeaders.Add("X-Api-Key", clientID);

                                    var JSONContent = new StringContent(updateAdobeUser.ToString(), Encoding.UTF8, "application/json");

                                    var responseAdobe = myHttpClient.PostAsync("https://usermanagement.adobe.io/v2/usermanagement/action/" + orgID, JSONContent);
                                    var updateContents = responseAdobe.Result.Content.ReadAsStringAsync();

                                    // 429 = too many requests... try again
                                    if (responseAdobe.Result.StatusCode.ToString().Equals("429"))
                                    {
                                        tooManyRequests = true;
                                    }
                                    else if (responseAdobe.Result.StatusCode.ToString().Equals("OK"))
                                    {
                                        tooManyRequests = false;
                                        JObject adobeJob = JObject.Parse(updateContents.Result);

                                        if (adobeJob["result"].ToString().Equals("success"))
                                        {
                                            log.Info("Successfully updated " + csentryChange.DN + ".");
                                        }
                                        else if (adobeJob["result"].ToString().Equals("error"))
                                        {
                                            log.Info("Unable to modify user: " + csentryChange.DN + ". Error: " + adobeJob["errors"].ToString());
                                            exportResult = MAExportError.ExportErrorCustomContinueRun;
                                            exportEntriesResults.CSEntryChangeResults.Add(
                                                CSEntryChangeResult.Create(csentryChange.Identifier, attributeChanges, exportResult, "Adobe API Error", adobeJob["errors"].ToString()));
                                            continue;
                                        }
                                        else
                                        {
                                            log.Info("Unable to modify user: " + csentryChange.DN + ". Error: " + adobeJob.ToString());
                                            exportResult = MAExportError.ExportErrorCustomContinueRun;
                                            exportEntriesResults.CSEntryChangeResults.Add(
                                                CSEntryChangeResult.Create(csentryChange.Identifier, attributeChanges, exportResult, "Adobe API Error", adobeJob.ToString()));
                                            continue;
                                        }
                                    }
                                    else
                                    {
                                        log.Info("Somethign else is up.. " + responseAdobe.Result.StatusCode);
                                    }
                                }
                                catch (Exception e)
                                {
                                    log.Info("Unable to modify user: " + csentryChange.DN + ". Error: " + e.Message);
                                    exportResult = MAExportError.ExportErrorCustomContinueRun;
                                    exportEntriesResults.CSEntryChangeResults.Add(
                                        CSEntryChangeResult.Create(csentryChange.Identifier, attributeChanges, exportResult, "Unexpected Error", e.Message));
                                    continue;
                                }
                            } while (tooManyRequests);
                        }
                        #endregion
                        #region Update Group
                        else if (csentryChange.ObjectType == "group")
                        {
                            string errMessage = "";

                            log.Info("Number of changes... " + csentryChange.AttributeChanges.Count);
                            foreach (AttributeChange ch in csentryChange.AttributeChanges)
                            {
                                log.Info(String.Format("Getting group: {0} {1} {2}", csentryChange.DN, ch.ModificationType, ch.IsMultiValued));
                                switch (ch.Name)
                                {
                                    case "member":
                                        foreach (ValueChange vch in ch.ValueChanges)
                                        {
                                            switch (vch.ModificationType)
                                            {
                                                case ValueModificationType.Add:
                                                    try
                                                    {
                                                        log.Info("Adding " + ch.Name + "||" + vch.ModificationType.ToString() + "||" + vch.Value.ToString());

                                                        JArray addAdobeUser = new JArray();
                                                        JObject user = new JObject();
                                                        user["user"] = vch.Value.ToString();
                                                        user["domain"] = "csuci.edu";
                                                        user["requestID"] = "action_1";

                                                        JArray doArray = new JArray();
                                                        JObject action = new JObject();
                                                        JObject groups = new JObject();
                                                        JArray groupsArray = new JArray();
                                                        JValue group = new JValue(csentryChange.DN);

                                                        groupsArray.Add(group);
                                                        groups["group"] = groupsArray;
                                                        action["add"] = groups;
                                                        doArray.Add(action);
                                                        user["do"] = doArray;
                                                        addAdobeUser.Add(user);

                                                        bool tooManyRequests = false;

                                                        do
                                                        {
                                                            var myHttpClient = new HttpClient();

                                                            myHttpClient.DefaultRequestHeaders.Add("Authorization", "Bearer " + JWTToken["access_token"]);
                                                            myHttpClient.DefaultRequestHeaders.Add("X-Api-Key", clientID);

                                                            var JSONContent = new StringContent(addAdobeUser.ToString(), Encoding.UTF8, "application/json");

                                                            var responseAdobe = myHttpClient.PostAsync("https://usermanagement.adobe.io/v2/usermanagement/action/" + orgID, JSONContent);
                                                            var updateContents = responseAdobe.Result.Content.ReadAsStringAsync();

                                                            // 429 = too many requests... try again
                                                            if (responseAdobe.Result.StatusCode.ToString().Equals("429"))
                                                            {
                                                                tooManyRequests = true;
                                                                //errMessage = "Successfully added user " + csentryChange.DN + " to the group " + csentryChange.DN + ". Adobe API returned code 429 - too many requests!";
                                                                log.Info("Unable to add user: " + vch.Value.ToString() + " to the group " + csentryChange.DN + " Error: Too many requests!");
                                                                Thread.Sleep(60000);
                                                            }
                                                            // 200 = OK - JSON Response given
                                                            else if (responseAdobe.Result.StatusCode.ToString().Equals("OK"))
                                                            {
                                                                tooManyRequests = false;
                                                                JObject adobeJob = JObject.Parse(updateContents.Result);
                                                                if (adobeJob["result"].ToString().Equals("success"))
                                                                {
                                                                    log.Info("Successfully added user " + csentryChange.DN + " to the group " + csentryChange.DN + ".");
                                                                }
                                                                else if (adobeJob["result"].ToString().Equals("error"))
                                                                {
                                                                    log.Info("Unable to add user: " + vch.Value.ToString() + " to the group " + csentryChange.DN + ". Error: " + adobeJob["errors"].ToString());
                                                                    errMessage = adobeJob["errors"].ToString();
                                                                    exportResult = MAExportError.ExportErrorCustomContinueRun;
                                                                    continue;
                                                                }
                                                                else
                                                                {
                                                                    log.Info("Unable to add user: " + vch.Value.ToString() + " to the group " + csentryChange.DN + ". Error: " + adobeJob.ToString());
                                                                    errMessage = adobeJob.ToString();
                                                                    exportResult = MAExportError.ExportErrorCustomContinueRun;
                                                                    continue;
                                                                }
                                                            }
                                                            else
                                                            {
                                                                log.Info("Somethign else is up.. " + responseAdobe.Result.StatusCode);
                                                            }
                                                        } while (tooManyRequests);     
                                                    }
                                                    catch (Exception e)
                                                    {
                                                        log.Info("Unable to add user: " + vch.Value.ToString() + " to the group " + csentryChange.DN + ". Error: " + e.Message);
                                                        exportResult = MAExportError.ExportErrorCustomContinueRun;
                                                        errMessage = e.Message;
                                                        continue;
                                                    }

                                                    break;
                                                case ValueModificationType.Delete:
                                                    try
                                                    {
                                                        JArray removeAdobeUser = new JArray();
                                                        JObject user = new JObject();
                                                        user["user"] = vch.Value.ToString();
                                                        user["domain"] = "csuci.edu";
                                                        user["requestID"] = "action_1";

                                                        JArray doArray = new JArray();
                                                        JObject action = new JObject();
                                                        JObject groups = new JObject();
                                                        JArray groupsArray = new JArray();
                                                        JValue group = new JValue(csentryChange.DN);

                                                        groupsArray.Add(group);
                                                        groups["group"] = groupsArray;
                                                        action["remove"] = groups;
                                                        doArray.Add(action);
                                                        user["do"] = doArray;
                                                        removeAdobeUser.Add(user);

                                                        var myHttpClient = new HttpClient();

                                                        myHttpClient.DefaultRequestHeaders.Add("Authorization", "Bearer " + JWTToken["access_token"]);
                                                        myHttpClient.DefaultRequestHeaders.Add("X-Api-Key", clientID);

                                                        var JSONContent = new StringContent(removeAdobeUser.ToString(), Encoding.UTF8, "application/json");

                                                        var responseAdobe = myHttpClient.PostAsync("https://usermanagement.adobe.io/v2/usermanagement/action/" + orgID, JSONContent);
                                                        var updateContents = responseAdobe.Result.Content.ReadAsStringAsync();

                                                        // 429 = too many requests... try again
                                                        if (responseAdobe.Result.StatusCode.ToString().Equals("429"))
                                                        {
                                                            errMessage = "Successfully added user " + csentryChange.DN + " to the group " + csentryChange.DN + ". Adobe API returned code 429 - too many requests!";
                                                            //log.Info("Too many requests!");
                                                        }
                                                        // 200 = OK - JSON Response given
                                                        else if (responseAdobe.Result.StatusCode.ToString().Equals("200"))
                                                        {
                                                            JObject adobeJob = JObject.Parse(updateContents.Result);

                                                            if (adobeJob["result"].ToString().Equals("success"))
                                                            {
                                                                log.Info("Successfully updated " + csentryChange.DN + ".");
                                                            }
                                                            else if (adobeJob["result"].ToString().Equals("error"))
                                                            {
                                                                log.Info("Unable to remove user: " + vch.Value.ToString() + " from the group " + csentryChange.DN + ". Error: " + adobeJob["errors"].ToString());
                                                                errMessage = adobeJob["errors"].ToString();
                                                                exportResult = MAExportError.ExportErrorCustomContinueRun;
                                                                continue;
                                                            }
                                                            else
                                                            {
                                                                log.Info("Unable to remove user: " + vch.Value.ToString() + " from the group " + csentryChange.DN + ". Error: " + adobeJob.ToString());
                                                                errMessage = adobeJob.ToString();
                                                                exportResult = MAExportError.ExportErrorCustomContinueRun;
                                                                continue;
                                                            }
                                                        }   
                                                    }
                                                    catch (Exception e)
                                                    {
                                                        log.Info("Unable to remove user: " + vch.Value.ToString() + " from the group " + csentryChange.DN + ". Error: " + e.Message);
                                                        exportResult = MAExportError.ExportErrorCustomContinueRun;
                                                        errMessage = e.Message;
                                                        continue;
                                                    }
                                                    break;
                                            }
                                        }
                                        break;
                                }
                            }
                            exportEntriesResults.CSEntryChangeResults.Add(CSEntryChangeResult.Create(csentryChange.Identifier, attributeChanges, exportResult, "Google API Error", errMessage));
                        }
                        #endregion
                        break;
                    case ObjectModificationType.Delete:
                        #region Delete User
                        if (csentryChange.ObjectType == "user")
                        {
                            log.Info("Deleting " + csentryChange.DN + ".");

                            JArray deleteAdobeUser = new JArray();
                            JObject user = new JObject();
                            JArray doDelete = new JArray();
                            JObject delete = new JObject();
                            JObject deleteDetails = new JObject();

                            deleteDetails["deleteAccount"] = false;
                            delete["removeFromOrg"] = deleteDetails;
                            doDelete.Add(delete);                          

                            user["user"] = csentryChange.DN.Split('@')[0];
                            user["requestID"] = "action_1";
                            user["domain"] = csentryChange.DN.Split('@')[1];
                            user["do"] = doDelete;

                            deleteAdobeUser.Add(user);

                            bool tooManyRequests = false;

                            do
                            {
                                try
                                {
                                    log.Info("Attempting to delete user " + csentryChange.DN + ".");
                                    var myHttpClient = new HttpClient();

                                    myHttpClient.DefaultRequestHeaders.Add("Authorization", "Bearer " + JWTToken["access_token"]);
                                    myHttpClient.DefaultRequestHeaders.Add("X-Api-Key", clientID);

                                    var JSONContent = new StringContent(deleteAdobeUser.ToString(), Encoding.UTF8, "application/json");

                                    var responseAdobe = myHttpClient.PostAsync("https://usermanagement.adobe.io/v2/usermanagement/action/" + orgID, JSONContent);
                                    var updateContents = responseAdobe.Result.Content.ReadAsStringAsync();

                                    // 429 = too many requests... try again
                                    if (responseAdobe.Result.StatusCode.ToString().Equals("429"))
                                    {
                                        tooManyRequests = true;
                                    }
                                    else if (responseAdobe.Result.StatusCode.ToString().Equals("OK"))
                                    {
                                        tooManyRequests = false;
                                        JObject adobeJob = JObject.Parse(updateContents.Result);

                                        if (adobeJob["result"].ToString().Equals("success"))
                                        {
                                            log.Info("Successfully deleted " + csentryChange.DN + ".");
                                        }
                                        else if (adobeJob["result"].ToString().Equals("error"))
                                        {
                                            log.Info("Unable to delete user: " + csentryChange.DN + ". Error: " + adobeJob["errors"].ToString());
                                            exportResult = MAExportError.ExportErrorCustomContinueRun;
                                            exportEntriesResults.CSEntryChangeResults.Add(
                                                CSEntryChangeResult.Create(csentryChange.Identifier, attributeChanges, exportResult, "Adobe API Error", adobeJob["errors"].ToString()));
                                            continue;
                                        }
                                        else
                                        {
                                            log.Info("Unable to delete user: " + csentryChange.DN + ". Error: " + adobeJob.ToString());
                                            exportResult = MAExportError.ExportErrorCustomContinueRun;
                                            exportEntriesResults.CSEntryChangeResults.Add(
                                                CSEntryChangeResult.Create(csentryChange.Identifier, attributeChanges, exportResult, "Adobe API Error", adobeJob.ToString()));
                                            continue;
                                        }
                                    }
                                    else
                                    {
                                        log.Info("Something else is up.. " + responseAdobe.Result.StatusCode);
                                    }
                                }
                                catch (Exception e)
                                {
                                    log.Info("Unable to delete user: " + csentryChange.DN + ". Error: " + e.Message);
                                    exportResult = MAExportError.ExportErrorCustomContinueRun;
                                    exportEntriesResults.CSEntryChangeResults.Add(
                                        CSEntryChangeResult.Create(csentryChange.Identifier, attributeChanges, exportResult, "Unexpected Error", e.Message));
                                    continue;
                                }
                            } while (tooManyRequests);
                        }
                        break;
                    #endregion
                    default:
                        break;
                }
            }

            return exportEntriesResults;
        }

        public void CloseExportConnection(CloseExportConnectionRunStep exportRunStep)
        {
        }

        public int ImportMaxPageSize
        {
            get
            {
                return m_importMaxPageSize;
            }
        }

        public int ImportDefaultPageSize
        {
            get
            {
                return m_importDefaultPageSize;
            }
        }

        public int ExportDefaultPageSize
        {
            get
            {
                return m_exportDefaultPageSize;
            }
            set
            {
                m_exportDefaultPageSize = value;
            }
        }

        public int ExportMaxPageSize
        {
            get
            {
                return m_exportMaxPageSize;
            }
            set
            {
                m_exportMaxPageSize = value;
            }
        }
    };
}
