import logging
from typing import Any, MutableMapping, Optional
from cloudformation_cli_python_lib import (
    BaseHookHandlerRequest,
    HandlerErrorCode,
    Hook,
    HookInvocationPoint,
    OperationStatus,
    ProgressEvent,
    SessionProxy,
    exceptions,
)

from .models import HookHandlerRequest, TypeConfigurationModel

# Use this logger to forward log messages to CloudWatch Logs.
LOG = logging.getLogger(__name__)
LOG.setLevel(logging.DEBUG)
TYPE_NAME = "MyCompany::S3::Log"

hook = Hook(TYPE_NAME, TypeConfigurationModel)
test_entrypoint = hook.test_entrypoint


@hook.handler(HookInvocationPoint.CREATE_PRE_PROVISION)
def pre_create_handler(
        session: Optional[SessionProxy],
        request: HookHandlerRequest,
        callback_context: MutableMapping[str, Any],
        type_configuration: TypeConfigurationModel
) -> ProgressEvent:
    target_model = request.hookContext.targetModel
    progress: ProgressEvent = ProgressEvent(
        status=OperationStatus.IN_PROGRESS
    )
    try:
        # Reading the Resource Hook's target properties
        resource_properties = target_model.get("resourceProperties")
        LOG.debug(f"DEBUG Details of resource_properties: {resource_properties}")
        LOG.debug(f"DEBUG Details of type_configuration: {type_configuration}")

        progress.status = OperationStatus.SUCCESS
    except TypeError as e:
        # exceptions module lets CloudFormation know the type of failure that occurred
        raise exceptions.InternalFailure(f"was not expecting type {e}")
        # this can also be done by returning a failed progress event
        # return ProgressEvent.failed(HandlerErrorCode.InternalFailure, f"was not expecting type {e}")

    return progress


@hook.handler(HookInvocationPoint.UPDATE_PRE_PROVISION)
def pre_update_handler(
        session: Optional[SessionProxy],
        request: BaseHookHandlerRequest,
        callback_context: MutableMapping[str, Any],
        type_configuration: TypeConfigurationModel
) -> ProgressEvent:
    target_model = request.hookContext.targetModel
    progress: ProgressEvent = ProgressEvent(
        status=OperationStatus.IN_PROGRESS
    )
    try:
        resource_properties = target_model.get("resourceProperties")
        LOG.debug(f"DEBUG Details of resource_properties: {resource_properties}")
        
        previous_properties = target_model.get("previousResourceProperties")
        LOG.debug(f"DEBUG Details of previous_properties: {previous_properties}")
        
        progress.status = OperationStatus.SUCCESS
    except TypeError as e:
        progress = ProgressEvent.failed(HandlerErrorCode.InternalFailure, f"was not expecting type {e}")

    return progress


@hook.handler(HookInvocationPoint.DELETE_PRE_PROVISION)
def pre_delete_handler(
        session: Optional[SessionProxy],
        request: BaseHookHandlerRequest,
        callback_context: MutableMapping[str, Any],
        type_configuration: TypeConfigurationModel
) -> ProgressEvent:
    # TODO: put code here
    return ProgressEvent(
        status=OperationStatus.SUCCESS
    )
