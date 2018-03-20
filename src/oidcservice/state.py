

def store_auth_request(service_context, request_args=None, **kwargs):
    _state = State().from_json(service_context.get_state(request_args['state']))
    _state['auth_request'] = request_args.to_json()
    service_context.set_state(request_args['state'], _state.to_json())


def store_response(service_context, response=None, response_type='', **kwargs):
    try:
        _state_val = kwargs['state']
    except KeyError:
        try:
            _state_val = response['state']
        except KeyError:
            raise ValueError("Couldn't find value of state")

    _state = State().from_json(service_context.get_state(_state_val))
    _state[response_type] = response.to_json()
    service_context.set_state(_state_val, _state.to_json())


def get_state(service_context, state):
    _data = service_context.get_state(state)
    if _data is None:
        raise KeyError(state)

    return State().from_json(_data)


def get_item(service_context, item_cls, item_type, state):
    _state = get_state(service_context, state)
    return item_cls().from_json(_state[item_type])


def get_iss(service_context, state):
    _state = get_state(service_context, state)
    return _state.iss


def extend_request_args(request_args, service_context, item_cls, item_type,
                        state, parameters):

    item = get_item(service_context, item_cls, item_type, state)

    for parameter in parameters:
        try:
            request_args[parameter] = item[parameter]
        except KeyError:
            pass

    return request_args