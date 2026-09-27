// Auto-generated TypeScript types from .usm/features/*.usm
// Source: usm generate → .usm-workspace/openapi/openapi.yaml
// DO NOT EDIT — regenerate with: pnpm --filter usm generate

export interface ControlPlaneApi {
  id: string;
}

export interface PostV1ObjectsParams {
}

export interface PostV1ObjectsResponse {
  data: ControlPlaneApi;
}

export interface PostV1TokensParams {
}

export interface PostV1TokensResponse {
  data: ControlPlaneApi;
}

export interface DeleteV1Tokens{jti}Params {
}

export interface DeleteV1Tokens{jti}Response {
  data: ControlPlaneApi;
}

export interface GetV1AuditParams {
}

export interface GetV1AuditResponse {
  data: ControlPlaneApi;
}

export interface GetV1PoliciesParams {
}

export interface GetV1PoliciesResponse {
  data: ControlPlaneApi;
}

export interface PutV1PoliciesParams {
}

export interface PutV1PoliciesResponse {
  data: ControlPlaneApi;
}

export interface GetHealthzParams {
}

export interface GetHealthzResponse {
  data: ControlPlaneApi;
}

export interface ApiPaths {
  '/v1/objects': {
    Post: {
      params: PostV1ObjectsParams;
      response: PostV1ObjectsResponse;
    };
  };
  '/v1/tokens': {
    Post: {
      params: PostV1TokensParams;
      response: PostV1TokensResponse;
    };
  };
  '/v1/tokens/{jti}': {
    Delete: {
      params: DeleteV1Tokens{jti}Params;
      response: DeleteV1Tokens{jti}Response;
    };
  };
  '/v1/audit': {
    Get: {
      params: GetV1AuditParams;
      response: GetV1AuditResponse;
    };
  };
  '/v1/policies': {
    Get: {
      params: GetV1PoliciesParams;
      response: GetV1PoliciesResponse;
    };
    Put: {
      params: PutV1PoliciesParams;
      response: PutV1PoliciesResponse;
    };
  };
  '/healthz': {
    Get: {
      params: GetHealthzParams;
      response: GetHealthzResponse;
    };
  };
}