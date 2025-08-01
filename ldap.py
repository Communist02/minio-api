import os
from ldap3 import ALL, Server, Connection, MODIFY_REPLACE, core, AUTO_BIND_NO_TLS
print(os.getenv('LDAP_PASS'))


class LDAPManager:
    def __init__(self, server_url='ldap.eco.dvo.ru', admin_dn='cn=Manager,dc=eco,dc=dvo,dc=ru', admin_password=os.getenv('LDAP_PASS')):
        self.server_url = server_url
        self.admin_dn = admin_dn
        self.admin_password = admin_password
        self.users_base_dn = 'ou=users,dc=eco,dc=dvo,dc=ru'

    def _get_admin_connection(self) -> Connection:
        server = Server(self.server_url, 389, get_info=ALL)
        return Connection(server, self.admin_dn, self.admin_password, auto_bind=True)

    def auth(self, username, password) -> int | None:
        try:
            server = Server(self.server_url, get_info=ALL)
            user_dn = f'uid={username},{self.users_base_dn}'

            conn = Connection(server, user_dn, password, auto_bind=True)

            conn.search(
                search_base=self.users_base_dn,
                search_filter=f'(uid={username})',
                attributes=['uidNumber']
            )

            if conn.entries:
                user_id = conn.entries[0].uidNumber.value
            else:
                user_id = None

            conn.unbind()
            return user_id

        except core.exceptions.LDAPBindError:
            return None
        except core.exceptions.LDAPInvalidDnError:
            print(f'Неверный DN для пользователя {username}')
            return None
        except Exception as e:
            print(f'Ошибка аутентификации: {e}')
            return None

    def user_exists(self, username) -> int | None:
        conn = self._get_admin_connection()
        try:
            search_filter = f'(uid={username})'
            conn.search(
                search_base=self.users_base_dn,
                search_filter=search_filter,
                attributes=['uid']
            )

            if conn.entries:
                return conn.entries[0].uid.value
            return None
        except Exception as e:
            print(f'Ошибка при проверке пользователя: {e}')
            return None
        finally:
            conn.unbind()

    def create_user(self, username, password, **attributes) -> str:
        """
        Создание нового пользователя

        :param username: Логин нового пользователя
        :param password: Пароль нового пользователя
        :param attributes: Дополнительные атрибуты пользователя (например: givenName='John', mail='john@example.com')
        :return: DN созданного пользователя
        :raises: ValueError если пользователь уже существует
        :raises: Exception если не удалось создать пользователя
        """
        conn = self._get_admin_connection()
        try:
            if self.user_exists(username):
                raise ValueError(f"Пользователь {username} уже существует")

            user_dn = f'uid={username},{self.users_base_dn}'

            # Базовые атрибуты пользователя
            default_attributes = {
                'objectClass': ['inetOrgPerson', 'organizationalPerson', 'person', 'top'],
                'uid': username,
                'cn': username,
                'sn': username.split('.')[0] if '.' in username else username,
                'userPassword': password
            }

            # Объединяем с переданными атрибутами
            user_attributes = {**default_attributes, **attributes}

            if not conn.add(user_dn, attributes=user_attributes):
                raise Exception(
                    f"Ошибка при создании пользователя: {conn.result}")

            return user_dn
        finally:
            conn.unbind()

    def update_user(self, username, **attributes):
        conn = self._get_admin_connection()
        try:
            if not self.user_exists(username):
                raise ValueError(f"Пользователь {username} не существует")

            user_dn = f'uid={username},{self.users_base_dn}'
            changes = {key: [(MODIFY_REPLACE, [value])]
                       for key, value in attributes.items()}

            if not conn.modify(user_dn, changes):
                raise Exception(
                    f"Ошибка при обновлении пользователя: {conn.result}")

            return True
        finally:
            conn.unbind()

    def delete_user(self, username):
        """
        Удаление пользователя

        :param username: Логин пользователя для удаления
        :return: True если удаление прошло успешно
        :raises: ValueError если пользователь не существует
        """
        conn = self._get_admin_connection()
        try:
            if not self.user_exists(username):
                raise ValueError(f"Пользователь {username} не существует")

            user_dn = f'uid={username},{self.users_base_dn}'

            if not conn.delete(user_dn):
                raise Exception(
                    f"Ошибка при удалении пользователя: {conn.result}")

            return True
        finally:
            conn.unbind()


# Пример использования
if __name__ == "__main__":
    ldap_manager = LDAPManager()

    # Пример аутентификации
    username = "iivanov123"
    password = "123"
    print(ldap_manager.auth(username, password))

    if ldap_manager.auth(username, password):
        print(f"Пользователь {username} аутентифицирован успешно")
    else:
        print(f"Ошибка аутентификации для пользователя {username}")

    # Пример работы с пользователями (требует админских прав)
    new_user = "new.user"
    if not ldap_manager.user_exists(new_user):
        try:
            # Создаем пользователя
            user_dn = ldap_manager.create_user(
                username=new_user,
                password="SecurePass123",
                givenName="New",
                sn="User",
                mail="new.user@example.com",
                displayName="New User"
            )
            print(f"Создан пользователь: {user_dn}")

            # Обновляем пользователя
            ldap_manager.update_user(
                new_user, mail="updated.email@example.com")
            print(f"Пользователь {new_user} обновлен")

            # Проверяем аутентификацию
            if ldap_manager.authenticate(new_user, "SecurePass123"):
                print("Новый пользователь успешно аутентифицирован")

            # Удаляем пользователя (для демонстрации)
            ldap_manager.delete_user(new_user)
            print(f"Пользователь {new_user} удален")

        except Exception as e:
            print(f"Ошибка: {e}")
