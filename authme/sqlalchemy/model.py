"""Generic Auth Models
requires `apothecary`
"""


import apothecary.modelmix.auth
import apothecary.modelmix.sec


IdMix = apothecary.modelmix.id_mix(id_attr="id")
TsUpdatedMix = apothecary.modelmix.ts_mix("ts_updated", onupdate=True)
TsCreatedMix = apothecary.modelmix.ts_mix("ts_created", oncreate=True)
ActiveMix = apothecary.modelmix.flag_mix("active")
TokenMix = apothecary.modelmix.sec.url_token_mix(
                created_col="tk_created", created_token_size=8,
                updated_token='token_updated', updated_token_size=8)


class UserMix(IdMix, TsUpdatedMix, TsCreatedMix, ActiveMix, TokenMix,
              apothecary.modelmix.auth.user_mix()):
    """ """
    pass


class GroupMix(IdMix, TsUpdatedMix, TsCreatedMix, ActiveMix, TokenMix,
               apothecary.modelmix.auth.group_mix()):
    """ """
    pass


class PermissionMix(IdMix, apothecary.modelmix.auth.permission_mix()):
    """ """
    pass

