#!/usr/bin/env node

import {
  ListToolsRequestSchema,
  CallToolRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StreamableHTTPServerTransport, StreamableHTTPServerTransportOptions } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import http from 'http';
import axios from 'axios';

import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { zodToJsonSchema } from 'zod-to-json-schema';
import { WebClient } from '@slack/web-api';
import dotenv from 'dotenv';
import {
  ListChannelsRequestSchema,
  PostMessageRequestSchema,
  ReplyToThreadRequestSchema,
  AddReactionRequestSchema,
  GetChannelHistoryRequestSchema,
  GetThreadRepliesRequestSchema,
  GetUsersRequestSchema,
  GetUserProfileRequestSchema,
  ListChannelsResponseSchema,
  GetUsersResponseSchema,
  GetUserProfileResponseSchema,
  SearchMessagesRequestSchema,
  // SearchMessagesResponseSchema,
  ConversationsHistoryResponseSchema,
  ConversationsRepliesResponseSchema,
} from './schemas.js';

dotenv.config();

// if (!process.env.SLACK_BOT_TOKEN) {
//   console.error(
//     'SLACK_BOT_TOKEN is not set. Please set it in your environment or .env file.'
//   );
//   process.exit(1);
// }

// const userClient = new WebClient(process.env.SLACK_USER_TOKEN);

// Token cache structure
interface TokenCacheEntry {
  access_token: string;
  expires_at: number; // Timestamp when the token expires
}

// In-memory token cache
const tokenCache: Record<string, TokenCacheEntry> = {};

// One hour in milliseconds
const ONE_HOUR_MS = 60 * 60 * 1000;

const server = new Server(
  {
    name: 'slack-mcp-server',
    version: '0.0.1',
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

async function update_config_prod(userId: string, serverId: string, refreshToken: string, updateConfigUrl: string){
  try {
    const response = await axios.post(updateConfigUrl, null, {
      params: {
        user_id: userId,
        mcp_serverId: serverId,
        config:{
          'SLACK_REFRESH_TOKEN': refreshToken,
        },
        scope: 'private',
      }
    });
    console.error(response?.data);
  } catch (error) {
    console.error('Error update user config:', error);
    throw new Error('Error update user config');
  }
}

/**
 * Refreshes the Slack access token using a refresh token
 * @param clientId The Slack client ID
 * @param clientSecret The Slack client secret
 * @param refresh_token The refresh token to use for refreshing the access token
 * @returns An object containing the new access token and other OAuth information
 */
async function refreshAccessToken(clientId: string, clientSecret: string, refresh_token: string, userId: string, serverId: string, updateConfigUrl: string) {
  try {
    const response = await axios.post('https://slack.com/api/oauth.v2.access', null, {
      params: {
        client_id: clientId,
        client_secret: clientSecret,
        grant_type: 'refresh_token',
        refresh_token: refresh_token
      },
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      }
    });

    if (!response.data.ok) {
      throw new Error(`Failed to refresh token: ${response.data.error}`);
    }

    await update_config_prod(userId, serverId, response.data.refresh_token || '', updateConfigUrl)


    return {
      access_token: response.data.access_token,
      refresh_token: response.data.refresh_token || refresh_token, // Use new refresh token if provided, otherwise keep the old one
      expires_in: response.data.expires_in
    };
  } catch (error) {
    console.error('Error refreshing access token:', error);
    throw new Error('Failed to refresh access token');
  }
}

/**
 * Gets a valid access token, either from cache or by refreshing
 * @param userId The user ID for cache key
 * @param serverId The server ID for cache key
 * @param clientId The Slack client ID
 * @param clientSecret The Slack client secret
 * @param refresh_token The refresh token
 * @param updateConfigUrl Url of update config
 * @returns A valid access token
 */
async function getValidAccessToken(
  userId: string,
  serverId: string,
  clientId: string,
  clientSecret: string,
  refresh_token: string,
  updateConfigUrl: string
): Promise<string> {
  const cacheKey = `${userId}:${serverId}`;
  const now = Date.now();
  const cachedToken = tokenCache[cacheKey];

  // If we have a cached token that's not expired, use it
  if (cachedToken && cachedToken.expires_at > now) {
    console.log(`Using cached token for ${cacheKey}, expires in ${Math.round((cachedToken.expires_at - now) / 1000)} seconds`);
    return cachedToken.access_token;
  }

  // Otherwise, we need to refresh the token and wait for it
  console.log(`Refreshing token for ${cacheKey}`);
  const tokenData = await refreshAccessToken(clientId, clientSecret, refresh_token, userId, serverId, updateConfigUrl);
  
  // Cache the new token with expiration (1 hour or less if specified by Slack)
  const expiresIn = tokenData.expires_in ? tokenData.expires_in * 1000 : ONE_HOUR_MS;
  tokenCache[cacheKey] = {
    access_token: tokenData.access_token,
    expires_at: now + expiresIn
  };
  
  return tokenData.access_token;
}

server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: [
      {
        name: 'slack_list_channels',
        description: 'List public channels in the workspace with pagination',
        inputSchema: zodToJsonSchema(ListChannelsRequestSchema),
      },
      {
        name: 'slack_post_message',
        description: 'Post a new message to a Slack channel',
        inputSchema: zodToJsonSchema(PostMessageRequestSchema),
      },
      {
        name: 'slack_reply_to_thread',
        description: 'Reply to a specific message thread in Slack',
        inputSchema: zodToJsonSchema(ReplyToThreadRequestSchema),
      },
      {
        name: 'slack_add_reaction',
        description: 'Add a reaction emoji to a message',
        inputSchema: zodToJsonSchema(AddReactionRequestSchema),
      },
      {
        name: 'slack_get_channel_history',
        description: 'Get recent messages from a channel',
        inputSchema: zodToJsonSchema(GetChannelHistoryRequestSchema),
      },
      {
        name: 'slack_get_thread_replies',
        description: 'Get all replies in a message thread',
        inputSchema: zodToJsonSchema(GetThreadRepliesRequestSchema),
      },
      {
        name: 'slack_get_users',
        description:
          'Retrieve basic profile information of all users in the workspace',
        inputSchema: zodToJsonSchema(GetUsersRequestSchema),
      },
      {
        name: 'slack_get_user_profile',
        description: "Get a user's profile information",
        inputSchema: zodToJsonSchema(GetUserProfileRequestSchema),
      },
      // {
      //   name: 'slack_search_messages',
      //   description: 'Search for messages in the workspace',
      //   inputSchema: zodToJsonSchema(SearchMessagesRequestSchema),
      // },
    ],
  };
});

server.setRequestHandler(CallToolRequestSchema, async (request, extra) => {
  try {
    if (!request.params) {
      throw new Error('Params are required');
    }
    const headers = extra?.requestInfo?.headers;

    const clientId: any = headers?.slack_client_id;
    const clientSecret: any = headers?.slack_client_secret;
    const refresh_token: any = headers?.slack_refresh_token;
    const userId: any = headers?.user_id;
    const serverId: any = headers?.server_id;
    const updateConfigUrl: any = headers?.update_config_url;
    let access_token: any = headers?.slack_access_token;


    if(!userId || !serverId){
      throw new Error('User id or server id is missing');
    }

    if(!refresh_token){
      throw new Error("Refresh token is required");
    }

    if (!clientId || !clientSecret) {
      throw new Error('SLACK_CLIENT_ID and SLACK_CLIENT_SECRET missing');
    }

    if (!updateConfigUrl) {
      throw new Error('Update config URL is required');
    }

    // Get a valid access token (from cache or refresh if needed)
    try {
      access_token = await getValidAccessToken(
        userId,
        serverId,
        clientId,
        clientSecret,
        refresh_token,
        updateConfigUrl
      );
    } catch (tokenError) {
      console.error('Failed to get valid access token:', tokenError);
      throw new Error('Failed to authenticate with Slack');
    }

    // Initialize Slack client with the access token
    const slackClient = new WebClient(access_token);
    
    switch (request.params.name) {
      case 'slack_list_channels': {
        const args = ListChannelsRequestSchema.parse(request.params.arguments);
        const response = await slackClient.conversations.list({
          limit: args.limit,
          cursor: args.cursor,
          types: 'public_channel', // Only public channels
        });
        if (!response.ok) {
          throw new Error(`Failed to list channels: ${response.error}`);
        }
        const parsed = ListChannelsResponseSchema.parse(response);

        return {
          content: [{ type: 'text', text: JSON.stringify(parsed) }],
        };
      }

      case 'slack_post_message': {
        const args = PostMessageRequestSchema.parse(request.params.arguments);
        const response = await slackClient.chat.postMessage({
          channel: args.channel_id,
          text: args.text,
        });
        if (!response.ok) {
          throw new Error(`Failed to post message: ${response.error}`);
        }
        return {
          content: [{ type: 'text', text: 'Message posted successfully' }],
        };
      }

      case 'slack_reply_to_thread': {
        const args = ReplyToThreadRequestSchema.parse(request.params.arguments);
        const response = await slackClient.chat.postMessage({
          channel: args.channel_id,
          thread_ts: args.thread_ts,
          text: args.text,
        });
        if (!response.ok) {
          throw new Error(`Failed to reply to thread: ${response.error}`);
        }
        return {
          content: [
            { type: 'text', text: 'Reply sent to thread successfully' },
          ],
        };
      }
      case 'slack_add_reaction': {
        const args = AddReactionRequestSchema.parse(request.params.arguments);
        const response = await slackClient.reactions.add({
          channel: args.channel_id,
          timestamp: args.timestamp,
          name: args.reaction,
        });
        if (!response.ok) {
          throw new Error(`Failed to add reaction: ${response.error}`);
        }
        return {
          content: [{ type: 'text', text: 'Reaction added successfully' }],
        };
      }

      case 'slack_get_channel_history': {
        const args = GetChannelHistoryRequestSchema.parse(
          request.params.arguments
        );
        const response = await slackClient.conversations.history({
          channel: args.channel_id,
          limit: args.limit,
          cursor: args.cursor,
        });
        if (!response.ok) {
          throw new Error(`Failed to get channel history: ${response.error}`);
        }
        const parsedResponse =
          ConversationsHistoryResponseSchema.parse(response);
        return {
          content: [{ type: 'text', text: JSON.stringify(parsedResponse) }],
        };
      }

      case 'slack_get_thread_replies': {
        const args = GetThreadRepliesRequestSchema.parse(
          request.params.arguments
        );
        const response = await slackClient.conversations.replies({
          channel: args.channel_id,
          ts: args.thread_ts,
          limit: args.limit,
          cursor: args.cursor,
        });
        if (!response.ok) {
          throw new Error(`Failed to get thread replies: ${response.error}`);
        }
        const parsedResponse =
          ConversationsRepliesResponseSchema.parse(response);
        return {
          content: [{ type: 'text', text: JSON.stringify(parsedResponse) }],
        };
      }

      case 'slack_get_users': {
        const args = GetUsersRequestSchema.parse(request.params.arguments);
        const response = await slackClient.users.list({
          limit: args.limit,
          cursor: args.cursor,
        });
        if (!response.ok) {
          throw new Error(`Failed to get users: ${response.error}`);
        }
        const parsed = GetUsersResponseSchema.parse(response);

        return {
          content: [{ type: 'text', text: JSON.stringify(parsed) }],
        };
      }

      case 'slack_get_user_profile': {
        const args = GetUserProfileRequestSchema.parse(
          request.params.arguments
        );
        const response = await slackClient.users.profile.get({
          user: args.user_id,
        });
        if (!response.ok) {
          throw new Error(`Failed to get user profile: ${response.error}`);
        }
        const parsed = GetUserProfileResponseSchema.parse(response);
        return {
          content: [{ type: 'text', text: JSON.stringify(parsed) }],
        };
      }

      default:
        throw new Error(`Unknown tool: ${request.params.name}`);
    }
  } catch (error) {
    console.error('Error handling request:', error);
    const errorMessage =
      error instanceof Error ? error.message : 'Unknown error occurred';
    throw new Error(errorMessage);
  }
});

async function runServer() {
  const port = parseInt(process.env.PORT || '3333');
  const options: StreamableHTTPServerTransportOptions = {
    sessionIdGenerator: undefined
  }
  const transport = new StreamableHTTPServerTransport(options);
  await server.connect(transport);

  // Create HTTP server to handle requests
  const httpServer = http.createServer((req, res) => {
    if (req.method === 'POST' && req.url === '/mcp') {
      let body = '';
      req.on('data', chunk => {
        body += chunk.toString();
      });
      req.on('end', async () => {
        try {
          res.setHeader('Content-Type', 'application/json');
          res.setHeader('Access-Control-Allow-Origin', '*');
          res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
          res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

          if (req.method === 'OPTIONS') {
            res.writeHead(200);
            res.end();
            return;
          }

          await transport.handleRequest(req, res, JSON.parse(body));
        } catch (error) {
          console.error('HTTP request error:', error);
          res.writeHead(500);
          res.end(JSON.stringify({ error: 'Internal server error' }));
        }
      });
    } else if (req.method === 'OPTIONS') {
      res.setHeader('Access-Control-Allow-Origin', '*');
      res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
      res.writeHead(200);
      res.end();
    } else {
      res.writeHead(400);
      res.end('Not Found');
    }
  });

  httpServer.listen(port, () => {
    console.error(`Slack MCP server running on HTTP port ${port}`);
  });
}

runServer().catch((error) => {
  console.error('Fatal error in main():', error);
  process.exit(1);
});
