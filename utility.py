# Time
from datetime import datetime
from datetime import timedelta
from pytz import timezone


"""""""""
General
"""""""""

# Check if input is filled or no
def is_filled(data):
   if data is None:
      return False
   if data == '':
      return False
   if data == []:
      return False
   if data == {}:
      return False
   if data == ():
      return False
   return True

"""
Time
"""
# My Default Timezone
def default_timezone():
    _tz = timezone('Europe/Rome')
    return(_tz)
    
# Now Time with Formatter or not
def my_time_now(_what_format = False):
    _my_timezone = default_timezone()
    if not _what_format:
        _now = datetime.now(_my_timezone)
    else:
        _now = datetime.now(_my_timezone).strftime("%Y-%m-%d %H:%M:%S")
    return(_now)

# TimeStamp milliseconds Formatter
def timestamp_formatter(_date):
    _my_timezone    = default_timezone()
    _my_date        = datetime.fromtimestamp(_date/1000, _my_timezone).strftime('%Y-%m-%d %H:%M:%S')
    return(_my_date)


"""""""""
STRING
"""""""""
def split_string_into_list(txt, separator):
    
    # Prepare
    _list = []
    _slices = None
    
    _slices = txt.split(separator)
    for _slice in _slices:
        if bool(_slice):
            if _slice == 'None':
                _slice = None
            _list.append(_slice)
            
    return(_list)

"""
Log
"""
def my_log(_type, _module, _func_name, _func_line, _inputs ,_msg,_clean=True):

    # Prepare
    _msg_error_complete = None
    _msg_return = None
    _response_split = None
    _where = f"{_module}.{_func_name}"
    
    # Build Error Msg
    if _inputs is not None:    
        _msg_error_complete = f"{_type} on {_where}, line {_func_line} with inputs {_inputs} -- MESSAGE: {my_time_now(True)} - {_type.upper()} - {_msg}"
    else:
        _msg_error_complete = f"{_type} on {_where}, line {_func_line} -- MESSAGE: {my_time_now(True)} - {_type.upper()} - {_msg}"
        
    
    # Return Nice Msg for Users or Not
    if _clean:
        _response_split = split_string_into_list(_msg_error_complete,'MESSAGE: ')
        if _response_split:
            _msg_return = _response_split[-1]
        else:
            _msg_return = _msg_error_complete
    else:
        _msg_return = _msg_error_complete
        
    return(_msg_return)
