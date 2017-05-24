test
# config context path to "/" by setting an empty string
server:
  contextPath:

# JACKSON
spring:
  jackson:
    serialization:
      INDENT_OUTPUT: true

jwt:
  header: Authorization
  secret: mySecret
  expiration: 604800
  route:
    authentication:
      path: auth
      refresh: refresh

#logging:
#  level:
#    org.springframework:
#      security: DEBUG
