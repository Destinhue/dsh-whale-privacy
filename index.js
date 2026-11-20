import { createGuard } from './lib/service.js';
import { createToolSpecs } from './lib/tools.js';

export const name = 'dsh-whale-privacy';
export const inject = ['tools'];

function loggerFor(ctx) {
  try {
    if (typeof ctx?.logger === 'function') return ctx.logger('dsh-whale-privacy');
  } catch { /* fall through */ }
  return ctx?.logger && typeof ctx.logger.warn === 'function' ? ctx.logger : console;
}

/**
 * DSH entry point.
 *
 * The plugin is intentionally fail-open for the agent runtime: if the vault cannot
 * be opened, the plugin logs and loads no tools rather than breaking every turn.
 * The gate itself is fail-closed only for the categories the config marks `block`.
 */
export function apply(ctx, rawConfig = {}) {
  const logger = loggerFor(ctx);
  let guard;
  try {
    guard = createGuard({ ctx, config: rawConfig, logger });
  } catch (error) {
    logger?.error?.(`[dsh-whale-privacy] 初始化失败，插件未启用：${String(error?.message || error)}`);
    return () => {};
  }

  const disposers = [];
  const on = typeof ctx?.on === 'function' ? ctx.on.bind(ctx) : null;

  if (on) {
    disposers.push(on('tools/pre-execute', (exec, next) => guard.preTool(exec, next)));
    disposers.push(on('tools/post-execute', (exec, result, next) => guard.postTool(exec, result, next)));
  }

  const promptDispose = guard.promptSection();
  if (typeof promptDispose === 'function') disposers.push(promptDispose);

  const tools = typeof ctx?.get === 'function' ? ctx.get('tools', false) : ctx?.tools;
  if (tools && typeof tools.register === 'function') {
    for (const spec of createToolSpecs(guard)) {
      try {
        const dispose = tools.register(spec);
        if (typeof dispose === 'function') disposers.push(dispose);
      } catch (error) {
        logger?.warn?.(`[dsh-whale-privacy] 工具 ${spec.name} 注册失败：${String(error?.message || error)}`);
      }
    }
  } else {
    logger?.warn?.('[dsh-whale-privacy] 未找到 tools 服务，跳过工具注册');
  }

  try {
    ctx?.provide?.('whalePrivacy', guard);
  } catch (error) {
    logger?.warn?.(`[dsh-whale-privacy] 服务注册失败：${String(error?.message || error)}`);
  }

  logger?.info?.(`[dsh-whale-privacy] 已启用；vault=${guard.status().vault.count} 条，audit=${guard.status().audit.count} 条`);
  return () => {
    for (const dispose of disposers.reverse()) {
      try { dispose(); } catch { /* ignore */ }
    }
  };
}
