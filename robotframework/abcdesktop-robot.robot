*** Settings ***
Library  Collections
Library  RequestsLibrary
Library  DateTime
Resource  variables.robot 

#
# authors
# main author Jean-Pierre RUBAGA
# additional author Alexandre DEVELY
#

*** Variables *** 
${ABCDESKTOP_SERVICE_URL_DOMAIN_IP}      ${HTTP_OR_HTTPS}://${ABCDESKTOP_HOSTNAME}

*** Test Cases ***

Check authentication
    [documentation]  Check authentication 
    # [Tags]    ld-service  auth
    Create Session  auth  ${ABCDESKTOP_SERVICE_URL_DOMAIN_IP}  disable_warnings=1
    ${auth_body}=  Create Dictionary  manager=${null}  provider=${AUTH_PROVIDER}  userid=${USER_ID}  password=${USER_PASSWORD}
    Log  auth params: ${auth_body}   console=True
    ${auth_header}=  Create Dictionary   Content-Type=application/json
    Log  auth header: ${auth_header}   console=True
    ${response}=  POST On Session  auth  /API/auth/auth  json=${auth_body}  headers=${auth_header}  expected_status=anything  timeout=15
    # Log   ${response.json()}  console=True
    Status Should Be   200   ${response}
    Set Suite Variable   ${jwt_user_token}   ${response.json()['result']['jwt_user_token']}
    # Log  ${jwt_user_token}   console=True
    # [Teardown]  Run Keyword If  ${response.status_code} == 200  Log  authentication succeded!  console=True
    # [Teardown]   Collect and send results to database for a service  authentication  ${response}

Launch a user desktop
    [documentation]  Launch a user desktop
    # [Tags]    ld-service
    Create Session  desktop  ${ABCDESKTOP_SERVICE_URL_DOMAIN_IP}   disable_warnings=1
    ${desktop_body}=   Create Dictionary  width=1280  height=641   hostname=${null}   timezone=Europe/Paris 
    ${desktop_header}=   Create Dictionary   Content-Type=application/json  abcauthorization=Bearer ${jwt_user_token}
    ${response}=  POST On Session   desktop   /API/composer/launchdesktop  json=${desktop_body}  headers=${desktop_header}  expected_status=anything  timeout=60
    # Log  ${response.json()}  console=True
    Status Should Be   200   ${response}
    Set Suite Variable   ${jwt_desktop_token}   ${response.json()['result']['authorization']}
    #Log  desktop token: ${jwt_desktop_token}   console=True
    #[Teardown]   Collect and send results to database for a service  launch-a-desktop   ${response}

Count desktop window list
    [documentation]  Count desktop window list
    [Tags]    ld-service
    Create Session  count  ${ABCDESKTOP_SERVICE_URL_DOMAIN_IP}   disable_warnings=1
    ${app_header}=   Create Dictionary   Content-Type=application/json  abcauthorization=Bearer ${jwt_desktop_token}
    ${response}=   GET On Session   count   /spawner/getwindowslist  headers=${app_header}  expected_status=anything
    Status Should Be   200   ${response}
    # Log  ${response.json()}  console=True
    # Log  ${response.json()['data']}  console=True
    ${desktop_list_len}=    evaluate    len(${response.json()['data']})
    Log    First getwindowslist ${desktop_list_len}    console=True
    Set Suite Variable   ${first_desktop_list_len}  ${desktop_list_len}   

Open user application
    [documentation]   Open user application
    [Tags]    ld-service
    Create Session  app  ${ABCDESKTOP_SERVICE_URL_DOMAIN_IP}   disable_warnings=1
    ${app_body}=   Create Dictionary  image=${REGISTRY_URL}/${CONTAINER_APP_TO_OPEN}  args=${None}  timezone=Europe/Paris
    ${app_header}=   Create Dictionary   Content-Type=application/json  abcauthorization=Bearer ${jwt_user_token}
    ${response}=  POST On Session   app   /API/composer/ocrun   json=${app_body}  headers=${app_header}  expected_status=anything  timeout=15
    Status Should Be   200   ${response}
    # Log  ${response.json()} console=True
    Set Suite Variable   ${app_to_run}   ${response.json()['result']['container_id']}
    # [Teardown]   Collect and send results to database for a service  open-an-app  ${response}
 
Get desktop window list
    [documentation]  Get desktop window list
    [Tags]    ld-service
    Create Session  app  ${ABCDESKTOP_SERVICE_URL_DOMAIN_IP}   disable_warnings=1
    ${app_header}=   Create Dictionary   Content-Type=application/json  abcauthorization=Bearer ${jwt_desktop_token}
    Log		desktop_list_len ${first_desktop_list_len}   console=True
    # x is a counter in second
    # to run MAX_TIMEOUT_IN_SECONDS_TO_START_AN_APPLICATION 
    ${x}=  Set Variable    1
    ${desktop_list_len}=  Set Variable    0

    WHILE    ${x} <= ${MAX_TIMEOUT_IN_SECONDS_TO_START_AN_APPLICATION}
        # Log    Trying counter ${x}/${MAX_TIMEOUT_IN_SECONDS_TO_START_AN_APPLICATION}  console=True
	${response}=  GET On Session   app   /spawner/getwindowslist  headers=${app_header}  expected_status=anything
     	Status Should Be   200   ${response}
    	${desktop_list_len}=    evaluate    len(${response.json()['data']})
	Log   ${x}/${MAX_TIMEOUT_IN_SECONDS_TO_START_AN_APPLICATION} number of windows ${desktop_list_len} > ${first_desktop_list_len}  console=True
        IF    ${desktop_list_len} > ${first_desktop_list_len}    BREAK
	Sleep   1s
        ${x} =    Evaluate    ${x} + 1
    END
    Should Be True    ${desktop_list_len} > ${first_desktop_list_len}

Logout from user desktop
    [documentation]  Logout from user desktop
    [Tags]    ld-service
    Create Session  logout  ${ABCDESKTOP_SERVICE_URL_DOMAIN_IP}   disable_warnings=1
    ${logout_body}=   Create Dictionary
    ${logout_header}=   Create Dictionary   Content-Type=application/json  abcauthorization=Bearer ${jwt_user_token}
    ${response}=  POST On Session   logout   /API/auth/logout   json=${logout_body}  headers=${logout_header}  expected_status=anything
    Log   ${response.json()}  console=True
    Status Should Be   200   ${response}
    # [Teardown]   Collect and send results to database for a service  logout  ${response}
