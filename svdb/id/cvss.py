

class SECURITY_PROTECTION_VALUES(object):
    """
    Contain info about SECURITY_PROTECTION_VALUES.
    @ivar SP_ALLOWS_ADMIN_ACCESS: ...
    @ivar SP_ALLOWS_USER_ACCESS: ...
    @ivar SP_ALLOWS_OTHER_ACCESS: ...
    @ivar SP_UNDEFINED: ...
    """
#TODO: make better comments

    SP_ALLOWS_ADMIN_ACCESS = 1
    SP_ALLOWS_USER_ACCESS = 2
    SP_ALLOWS_OTHER_ACCESS = 3
    SP_UNDEFINED = 4
    
    
    @classmethod
    def from_string(cls, value):
        if 'SP_ALLOWS_ADMIN_ACCESS' == value:
            return cls.SP_ALLOWS_ADMIN_ACCESS
        elif 'SP_ALLOWS_USER_ACCESS' == value:
            return cls.SP_ALLOWS_USER_ACCESS
        elif 'SP_ALLOWS_OTHER_ACCESS' == value:
            return cls.SP_ALLOWS_OTHER_ACCESS
        elif 'SP_UNDEFINED' == value:
            return cls.SP_UNDEFINED
        else:
            if not isinstance(value, str):
                raise TypeError("parameter 'value' must be a string")
            else:
                raise ValueError("parameter 'value' contains wrong data")
            
    @classmethod
    def to_string(cls, value):
        if cls.SP_ALLOWS_ADMIN_ACCESS == value:
            return 'SP_ALLOWS_ADMIN_ACCESS'
        elif cls.SP_ALLOWS_USER_ACCESS == value:
            return 'SP_ALLOWS_USER_ACCESS'
        elif cls.SP_ALLOWS_OTHER_ACCESS == value:
            return 'SP_ALLOWS_OTHER_ACCESS'
        elif cls.SP_UNDEFINED == value:
            return 'SP_UNDEFINED'
        elif None == value:
            return ''
        else:
            if not isinstance(value, int):
                raise TypeError("parameter 'value' must be an integer")
            else:
                raise ValueError("parameter 'value' contains wrong data")


class ACCESS_VECTOR_VALUES(object):
    """
    Contain info about ACCESS_VECTOR_VALUES.
    @ivar LOCAL: ...
    @ivar ADJACENT_NETWORK: ...
    @ivar NETWORK: ...
    """
#TODO: make better comments

    LOCAL = 1
    ADJACENT_NETWORK = 2
    NETWORK = 3
    
    
    @classmethod
    def from_string(cls, value):
        if 'LOCAL' == value:
            return cls.LOCAL
        elif 'ADJACENT_NETWORK' == value:
            return cls.ADJACENT_NETWORK
        elif 'NETWORK' == value:
            return cls.NETWORK
        else:
            if not isinstance(value, str):
                raise TypeError("parameter 'value' must be a string")
            else:
                raise ValueError("parameter 'value' contains wrong data")
            
    @classmethod
    def to_string(cls, value):
        if cls.LOCAL == value:
            return 'LOCAL'
        elif cls.ADJACENT_NETWORK == value:
            return 'ADJACENT_NETWORK'
        elif cls.NETWORK == value:
            return 'NETWORK'
        elif None == value:
            return ''
        else:
            if not isinstance(value, int):
                raise TypeError("parameter 'value' must be an integer")
            else:
                raise ValueError("parameter 'value' contains wrong data")


class ACCESS_COMPLEXITY_VALUES(object):
    """
    Contain info about ACCESS_COMPLEXITY_VALUES.
    @ivar HIGH: ...
    @ivar MEDIUM: ...
    @ivar LOW: ...
    """
#TODO: make better comments

    HIGH = 1
    MEDIUM = 2
    LOW = 3
    
    @classmethod
    def from_string(cls, value):
        if 'HIGH' == value:
            return cls.HIGH
        elif 'MEDIUM' == value:
            return cls.MEDIUM
        elif 'LOW' == value:
            return cls.LOW
        else:
            if not isinstance(value, str):
                raise TypeError("parameter 'value' must be a string")
            else:
                raise ValueError("parameter 'value' contains wrong data")
            
    @classmethod
    def to_string(cls, value):
        if cls.HIGH == value:
            return 'HIGH'
        elif cls.MEDIUM == value:
            return 'MEDIUM'
        elif cls.LOW == value:
            return 'LOW'
        elif None == value:
            return ''
        else:
            if not isinstance(value, int):
                raise TypeError("parameter 'value' must be an integer")
            else:
                raise ValueError("parameter 'value' contains wrong data")


class AUTHENTICATION_VALUES(object):
    """
    Contain info about AUTHENTICATION_VALUES.
    @ivar MULTIPLE: ...
    @ivar SINGLE: ...
    @ivar NONE: ...
    """
#TODO: make better comments

    MULTIPLE = 1
    SINGLE = 2
    NONE = 3

    @classmethod
    def from_string(cls, value):
        if 'MULTIPLE_INSTANCES' == value:
            return cls.MULTIPLE
        elif 'SINGLE_INSTANCE' == value:
            return cls.SINGLE
        elif 'NONE' == value:
            return cls.NONE
        else:
            if not isinstance(value, str):
                raise TypeError("parameter 'value' must be string")
            else:
                raise ValueError("parameter 'value' contains wrong data")
                
    @classmethod
    def to_string(cls, value):
        if cls.MULTIPLE == value:
            return 'MULTIPLE'
        elif cls.SINGLE == value:
            return 'SINGLE'
        elif cls.NONE == value:
            return 'NONE'
        elif None == value:
            return ''
        else:
            if not isinstance(value, int):
                raise TypeError("parameter 'value' must be an integer")
            else:
                raise ValueError("parameter 'value' contains wrong data")


class IMPACT_VALUES(object):
    """
    Contain info about IMPACT_VALUES.
    @ivar NONE: ...
    @ivar PARTIAL: ...
    @ivar COMPLETE: ...
    """
#TODO: make better comments
    
    NONE = 1
    PARTIAL = 2
    COMPLETE = 3
    
    @classmethod
    def from_string(cls, value):
        if 'NONE' == value:
            return cls.NONE
        elif 'PARTIAL' == value:
            return cls.PARTIAL
        elif 'COMPLETE' == value:
            return cls.COMPLETE
        else:
            if not isinstance(value, str):
                raise TypeError("parameter 'value' must be a string")
            else:
                raise ValueError("parameter 'value' contains wrong data")

    @classmethod
    def to_string(cls, value):
        if cls.NONE == value:
            return 'NONE'
        elif cls.PARTIAL == value:
            return 'PARTIAL'
        elif cls.COMPLETE == value:
            return 'COMPLETE'
        elif None == value:
            return ''
        else:
            if not isinstance(value, int):
                raise TypeError("parameter 'value' must be an integer")
            else:
                raise ValueError("parameter 'value' contains wrong data")


class CVSSBaseMetrics(object):
    """
    Contain info about cvss base metrics for vulnerability.
    @ivar score: double with value of metrics score.
    @ivar security_protection: SECURITY_PROTECTION_VALUES object with value of security protection.
    @ivar access_vector: ACCESS_VECTOR_VALUES object with value of access vector.
    @ivar access_complexity: ACCESS_COMPLEXITY_VALUES object with value of access complexity.
    @ivar authentication: AUTHENTICATION_VALUES object with value of authentication.
    @ivar confidentiality_impact: IMPACT_VALUES object with value of confidentiality impact.
    @ivar integrity_impact: IMPACT_VALUES object with value of integrity impact.
    @ivar availability_impact: IMPACT_VALUES object with value of availability impact.
    """
#TODO: make better comments
    
    __slots__ = ['score', 'security_protection', 'access_vector', 'access_complexity', 
                 'authentication', 'confidentiality_impact', 'integrity_impact', 
                 'availability_impact']
    
    def __init__(self):
        self.score = 0.0        
        self.security_protection = SECURITY_PROTECTION_VALUES.SP_UNDEFINED    
        self.access_vector = None
        self.access_complexity = None
        self.authentication = AUTHENTICATION_VALUES.NONE    
        self.confidentiality_impact = IMPACT_VALUES.NONE    
        self.integrity_impact = IMPACT_VALUES.NONE    
        self.availability_impact = IMPACT_VALUES.NONE

    def __str__(self):
        res = """
        score = %s, 
        security_protection = %s,     
        access_vector = %s, 
        access_complexity = %s, 
        authentication = %s,      
        confidentiality_impact = %s, 
        integrity_impact = %s,  
        availability_impact = %s
        """ % (self.score,
        SECURITY_PROTECTION_VALUES.to_string(self.security_protection),    
        ACCESS_VECTOR_VALUES.to_string(self.access_vector),
        ACCESS_COMPLEXITY_VALUES.to_string(self.access_complexity),
        AUTHENTICATION_VALUES.to_string(self.authentication),
        IMPACT_VALUES.to_string(self.confidentiality_impact),     
        IMPACT_VALUES.to_string(self.integrity_impact),   
        IMPACT_VALUES.to_string(self.availability_impact))
         
        return res