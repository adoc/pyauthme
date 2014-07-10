from __future__ import absolute_import

import sqlalchemy.orm.exc


__all__ = ('result_or_none', 'UserAdapter')


def result_or_none(query):
    try:
        return query()
    except sqlalchemy.orm.exc.NoResultFound:
        return None


class UserAdapter(object):
    """ """
    def __init__(self, Session, UserModel, GroupModel, username_attr="name"):
        self.Session = Session
        self.UserModel = UserModel
        self.GroupModel = GroupModel
        self._username_attr = username_attr

    def get_user_by_id(self, userid):
        return result_or_none(lambda:
                self.Session.query(self.UserModel).get(userid))

    def get_user_by_name(self, username):
        attr = getattr(self.UserModel, self._username_attr)
        return result_or_none(lambda:
                (self.Session.query(self.UserModel)
                        .filter(attr == username).one()))

