// Types of @openmoat/sdk/langchain. Structural: the config `createMiddleware`
// of `langchain` accepts (checked against langchain 1.6.6) without importing it.
import type { Guard, GuardOptions } from "./guard";

export interface LangChainOptions extends Omit<GuardOptions, "host"> {
  guard?: Guard;
}

export interface OpenMoatMiddlewareConfig {
  name: string;
  wrapToolCall(
    request: { toolCall: { name: string; args: Record<string, any>; id?: string }; [key: string]: any },
    handler: (request: any) => any,
  ): Promise<any>;
}

export function openmoatMiddleware(options?: LangChainOptions): OpenMoatMiddlewareConfig;
