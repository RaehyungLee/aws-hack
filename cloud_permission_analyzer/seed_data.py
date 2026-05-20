from cloud_permission_analyzer.neo4j_client import Neo4jClient


CONSTRAINTS = [
    "CREATE CONSTRAINT user_name IF NOT EXISTS FOR (n:User) REQUIRE n.name IS UNIQUE",
    "CREATE CONSTRAINT group_name IF NOT EXISTS FOR (n:Group) REQUIRE n.name IS UNIQUE",
    "CREATE CONSTRAINT role_name IF NOT EXISTS FOR (n:Role) REQUIRE n.name IS UNIQUE",
    "CREATE CONSTRAINT policy_name IF NOT EXISTS FOR (n:Policy) REQUIRE n.name IS UNIQUE",
    "CREATE CONSTRAINT statement_id IF NOT EXISTS FOR (n:Statement) REQUIRE n.sid IS UNIQUE",
    "CREATE CONSTRAINT action_name IF NOT EXISTS FOR (n:Action) REQUIRE n.name IS UNIQUE",
    "CREATE CONSTRAINT resource_arn IF NOT EXISTS FOR (n:Resource) REQUIRE n.arn IS UNIQUE",
    "CREATE CONSTRAINT service_name IF NOT EXISTS FOR (n:Service) REQUIRE n.name IS UNIQUE",
]

RESET_GRAPH = "MATCH (n) DETACH DELETE n"

SAMPLE_GRAPH = [
    """
    MERGE (alice:Identity:User {name: 'alice'})
      SET alice.account = '111111111111', alice.owner = 'Platform'
    MERGE (bob:Identity:User {name: 'bob'})
      SET bob.account = '111111111111', bob.owner = 'Finance'
    MERGE (carol:Identity:User {name: 'carol'})
      SET carol.account = '111111111111', carol.owner = 'Security'
    MERGE (developers:Identity:Group {name: 'Developers'})
      SET developers.owner = 'Platform'
    MERGE (security:Identity:Group {name: 'SecurityAuditors'})
      SET security.owner = 'Security'
    MERGE (alice)-[:MEMBER_OF]->(developers)
    MERGE (carol)-[:MEMBER_OF]->(security)
    """,
    """
    MERGE (deploy:Identity:Role {name: 'DeployRole'})
      SET deploy.account = '111111111111',
          deploy.trust = 'Developers group can assume this role'
    MERGE (lambdaAdmin:Identity:Role {name: 'LambdaAdminRole'})
      SET lambdaAdmin.account = '111111111111',
          lambdaAdmin.trust = 'Trusted by Lambda service and DeployRole pass-role flow'
    MERGE (readOnly:Identity:Role {name: 'ReadOnlyRole'})
      SET readOnly.account = '111111111111',
          readOnly.trust = 'Security auditors only'
    MERGE (breakGlass:Identity:Role {name: 'BreakGlassAdminRole'})
      SET breakGlass.account = '111111111111',
          breakGlass.trust = 'Emergency access'
    """,
    """
    MERGE (s3:Service {name: 's3'})
    MERGE (iam:Service {name: 'iam'})
    MERGE (sts:Service {name: 'sts'})
    MERGE (lambda:Service {name: 'lambda'})
    MERGE (dynamo:Service {name: 'dynamodb'})

    MERGE (assumeDeploy:Action {name: 'sts:AssumeRole'})-[:BELONGS_TO]->(sts)
    MERGE (passRole:Action {name: 'iam:PassRole'})-[:BELONGS_TO]->(iam)
    MERGE (createLambda:Action {name: 'lambda:CreateFunction'})-[:BELONGS_TO]->(lambda)
    MERGE (deleteObject:Action {name: 's3:DeleteObject'})-[:BELONGS_TO]->(s3)
    MERGE (deleteBucket:Action {name: 's3:DeleteBucket'})-[:BELONGS_TO]->(s3)
    MERGE (getObject:Action {name: 's3:GetObject'})-[:BELONGS_TO]->(s3)
    MERGE (listBucket:Action {name: 's3:ListBucket'})-[:BELONGS_TO]->(s3)
    MERGE (deleteTable:Action {name: 'dynamodb:DeleteTable'})-[:BELONGS_TO]->(dynamo)
    MERGE (iamWildcard:Action {name: 'iam:*'})-[:BELONGS_TO]->(iam)
    MERGE (adminWildcard:Action {name: '*:*'})
    """,
    """
    MERGE (prodBucket:Resource {
      arn: 'arn:aws:s3:::prod-bucket',
      name: 'prod-bucket',
      sensitivity: 'production'
    })
    MERGE (prodObjects:Resource {
      arn: 'arn:aws:s3:::prod-bucket/*',
      name: 'prod-bucket objects',
      sensitivity: 'production'
    })
    MERGE (devBucket:Resource {
      arn: 'arn:aws:s3:::dev-bucket',
      name: 'dev-bucket',
      sensitivity: 'development'
    })
    MERGE (publicReports:Resource {
      arn: 'arn:aws:s3:::public-reports',
      name: 'public-reports',
      sensitivity: 'internal',
      public: true
    })
    MERGE (customerTable:Resource {
      arn: 'arn:aws:dynamodb:us-east-1:111111111111:table/customer-data',
      name: 'customer-data',
      sensitivity: 'production'
    })
    MERGE (allResources:Resource {
      arn: '*',
      name: 'all resources',
      sensitivity: 'all'
    })
    """,
    """
    MERGE (devAssume:Policy {
      name: 'DevelopersAssumeDeploy',
      type: 'inline',
      risk: 'medium'
    })
    MERGE (devAssumeStmt:Statement {
      sid: 'DevelopersAssumeDeployStmt',
      effect: 'Allow'
    })
    MERGE (devAssume)-[:HAS_STATEMENT]->(devAssumeStmt)
    WITH devAssume, devAssumeStmt
    MATCH (developers:Group {name: 'Developers'})
    MATCH (deploy:Role {name: 'DeployRole'})
    MATCH (assumeDeploy:Action {name: 'sts:AssumeRole'})
    MERGE (developers)-[:ATTACHED_TO]->(devAssume)
    MERGE (devAssumeStmt)-[:ALLOWS]->(assumeDeploy)
    MERGE (devAssumeStmt)-[:ON_RESOURCE]->(deploy)
    MERGE (developers)-[:CAN_ASSUME {via: 'DevelopersAssumeDeploy'}]->(deploy)
    """,
    """
    MERGE (deployPolicy:Policy {
      name: 'DeployRolePassLambdaAdmin',
      type: 'inline',
      risk: 'high'
    })
    MERGE (passStmt:Statement {
      sid: 'DeployRoleCanPassLambdaAdmin',
      effect: 'Allow'
    })
    MERGE (createLambdaStmt:Statement {
      sid: 'DeployRoleCanCreateLambda',
      effect: 'Allow'
    })
    MERGE (deployPolicy)-[:HAS_STATEMENT]->(passStmt)
    MERGE (deployPolicy)-[:HAS_STATEMENT]->(createLambdaStmt)
    WITH deployPolicy, passStmt, createLambdaStmt
    MATCH (deploy:Role {name: 'DeployRole'})
    MATCH (lambdaAdmin:Role {name: 'LambdaAdminRole'})
    MATCH (allResources:Resource {arn: '*'})
    MATCH (passRole:Action {name: 'iam:PassRole'})
    MATCH (createLambda:Action {name: 'lambda:CreateFunction'})
    MERGE (deploy)-[:ATTACHED_TO]->(deployPolicy)
    MERGE (passStmt)-[:ALLOWS]->(passRole)
    MERGE (passStmt)-[:ON_RESOURCE]->(lambdaAdmin)
    MERGE (createLambdaStmt)-[:ALLOWS]->(createLambda)
    MERGE (createLambdaStmt)-[:ON_RESOURCE]->(allResources)
    MERGE (deploy)-[:CAN_PASS_ROLE {via: 'DeployRolePassLambdaAdmin'}]->(lambdaAdmin)
    MERGE (deploy)-[:CAN_CREATE_LAMBDA_WITH {via: 'DeployRolePassLambdaAdmin'}]->(lambdaAdmin)
    """,
    """
    MERGE (lambdaAdminPolicy:Policy {
      name: 'LambdaAdminS3ProductionAccess',
      type: 'managed',
      risk: 'critical'
    })
    MERGE (deleteProdObjects:Statement {
      sid: 'LambdaAdminCanDeleteProdObjects',
      effect: 'Allow'
    })
    MERGE (deleteProdBucket:Statement {
      sid: 'LambdaAdminCanDeleteProdBucket',
      effect: 'Allow'
    })
    MERGE (lambdaAdminPolicy)-[:HAS_STATEMENT]->(deleteProdObjects)
    MERGE (lambdaAdminPolicy)-[:HAS_STATEMENT]->(deleteProdBucket)
    WITH lambdaAdminPolicy, deleteProdObjects, deleteProdBucket
    MATCH (lambdaAdmin:Role {name: 'LambdaAdminRole'})
    MATCH (prodBucket:Resource {arn: 'arn:aws:s3:::prod-bucket'})
    MATCH (prodObjects:Resource {arn: 'arn:aws:s3:::prod-bucket/*'})
    MATCH (deleteObject:Action {name: 's3:DeleteObject'})
    MATCH (deleteBucket:Action {name: 's3:DeleteBucket'})
    MERGE (lambdaAdmin)-[:ATTACHED_TO]->(lambdaAdminPolicy)
    MERGE (deleteProdObjects)-[:ALLOWS]->(deleteObject)
    MERGE (deleteProdObjects)-[:ON_RESOURCE]->(prodObjects)
    MERGE (deleteProdBucket)-[:ALLOWS]->(deleteBucket)
    MERGE (deleteProdBucket)-[:ON_RESOURCE]->(prodBucket)
    """,
    """
    MERGE (readOnlyPolicy:Policy {
      name: 'SecurityReadOnly',
      type: 'managed',
      risk: 'low'
    })
    MERGE (readStmt:Statement {
      sid: 'SecurityReadS3',
      effect: 'Allow'
    })
    MERGE (readOnlyPolicy)-[:HAS_STATEMENT]->(readStmt)
    WITH readOnlyPolicy, readStmt
    MATCH (security:Group {name: 'SecurityAuditors'})
    MATCH (readOnly:Role {name: 'ReadOnlyRole'})
    MATCH (prodBucket:Resource {arn: 'arn:aws:s3:::prod-bucket'})
    MATCH (getObject:Action {name: 's3:GetObject'})
    MERGE (security)-[:ATTACHED_TO]->(readOnlyPolicy)
    MERGE (readOnly)-[:ATTACHED_TO]->(readOnlyPolicy)
    MERGE (readStmt)-[:ALLOWS]->(getObject)
    MERGE (readStmt)-[:ON_RESOURCE]->(prodBucket)
    MERGE (security)-[:CAN_ASSUME {via: 'SecurityReadOnly'}]->(readOnly)
    """,
    """
    MERGE (adminPolicy:Policy {
      name: 'AdministratorAccess',
      type: 'aws-managed',
      risk: 'critical'
    })
    MERGE (adminStmt:Statement {
      sid: 'AdministratorAccessStmt',
      effect: 'Allow'
    })
    MERGE (adminPolicy)-[:HAS_STATEMENT]->(adminStmt)
    WITH adminPolicy, adminStmt
    MATCH (breakGlass:Role {name: 'BreakGlassAdminRole'})
    MATCH (allResources:Resource {arn: '*'})
    MATCH (adminWildcard:Action {name: '*:*'})
    MERGE (breakGlass)-[:ATTACHED_TO]->(adminPolicy)
    MERGE (adminStmt)-[:ALLOWS]->(adminWildcard)
    MERGE (adminStmt)-[:ON_RESOURCE]->(allResources)
    """,
    """
    MERGE (publicPolicy:Policy {
      name: 'PublicReportsBucketPolicy',
      type: 'resource-policy',
      risk: 'medium'
    })
    MERGE (publicRead:Statement {
      sid: 'PublicReportsAnonymousRead',
      effect: 'Allow',
      principal: '*'
    })
    MERGE (publicPolicy)-[:HAS_STATEMENT]->(publicRead)
    WITH publicRead
    MATCH (publicReports:Resource {arn: 'arn:aws:s3:::public-reports'})
    MATCH (getObject:Action {name: 's3:GetObject'})
    MERGE (publicRead)-[:ALLOWS]->(getObject)
    MERGE (publicRead)-[:ON_RESOURCE]->(publicReports)
    """,
]


def seed_database(client: Neo4jClient, reset: bool = False) -> None:
    if reset:
        client.query(RESET_GRAPH)
    client.execute_many(CONSTRAINTS)
    client.execute_many(SAMPLE_GRAPH)
