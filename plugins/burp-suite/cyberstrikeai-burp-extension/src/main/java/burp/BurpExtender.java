package burp;

import javax.swing.*;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

public class BurpExtender implements IBurpExtender, IContextMenuFactory {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    private CyberStrikeAITab tab;
    private final CyberStrikeAIClient client = new CyberStrikeAIClient();
    private String lastInstruction = HttpMessageFormatter.defaultInstruction();
    private final AtomicBoolean historySyncing = new AtomicBoolean(false);

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();

        callbacks.setExtensionName("CyberStrikeAI Extension");

        this.tab = new CyberStrikeAITab();
        callbacks.addSuiteTab(tab);

        callbacks.registerContextMenuFactory(this);

        callbacks.printOutput("CyberStrikeAI extension loaded.");
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        List<JMenuItem> items = new ArrayList<>();

        JMenuItem sendItem = new JMenuItem("Send to CyberStrikeAI (stream test)");
        sendItem.addActionListener(e -> {
            IHttpRequestResponse[] selected = invocation.getSelectedMessages();
            if (selected == null || selected.length == 0) {
                return;
            }
            sendMessage(selected[0]);
        });

        JMenuItem historyItem = new JMenuItem("Send to CyberStrikeAI History");
        historyItem.addActionListener(e -> {
            IHttpRequestResponse[] selected = invocation.getSelectedMessages();
            if (selected == null || selected.length == 0) {
                return;
            }
            sendToHistory(selected);
        });

        items.add(sendItem);
        items.add(historyItem);
        return items;
    }

    /** 右键多选条目 → POST /api/http-flows（source=burp）。超 1000 条自动分批。 */
    private void sendToHistory(IHttpRequestResponse[] messages) {
        if (historySyncing.getAndSet(true)) {
            return;
        }
        try {
            CyberStrikeAIClient.Config cfg = tab.currentConfig();
            String token = tab.getToken();
            if (token == null || token.trim().isEmpty()) {
                historySyncing.set(false);
                JOptionPane.showMessageDialog(tab.getUiComponent(),
                        "Please click Validate first to obtain a token.",
                        "CyberStrikeAI", JOptionPane.WARNING_MESSAGE);
                return;
            }

            // Burp 旧 extender API 不暴露 history 条目时间戳，统一用同步时刻
            long ts = System.currentTimeMillis();
            List<CyberStrikeAIClient.FlowPayload> flows = new ArrayList<>();
            for (IHttpRequestResponse msg : messages) {
                if (msg == null || msg.getRequest() == null || msg.getRequest().length == 0) {
                    continue;
                }
                flows.add(CyberStrikeAIClient.flowFromMessage(helpers, msg, ts));
            }
            if (flows.isEmpty()) {
                historySyncing.set(false);
                JOptionPane.showMessageDialog(tab.getUiComponent(),
                        "所选条目中没有可同步的请求。",
                        "CyberStrikeAI", JOptionPane.WARNING_MESSAGE);
                return;
            }

            HistorySyncDialog.Result result = HistorySyncDialog.show(
                    tab.getUiComponent(), client, cfg, token, flows.size());
            if (result == null) {
                historySyncing.set(false);
                return;
            }

            Thread worker = new Thread(() -> {
                int imported = 0;
                int duplicates = 0;
                try {
                    for (int i = 0; i < flows.size(); i += CyberStrikeAIClient.MAX_FLOWS_PER_BATCH) {
                        List<CyberStrikeAIClient.FlowPayload> chunk = flows.subList(i,
                                Math.min(flows.size(), i + CyberStrikeAIClient.MAX_FLOWS_PER_BATCH));
                        CyberStrikeAIClient.ImportSummary summary =
                                client.importHttpFlows(cfg, token, result.projectId, chunk);
                        imported += summary.imported;
                        duplicates += summary.duplicates;
                    }
                    final int okImported = imported;
                    final int okDuplicates = duplicates;
                    SwingUtilities.invokeLater(() -> JOptionPane.showMessageDialog(tab.getUiComponent(),
                            "同步完成：导入 " + okImported + " 条，重复 " + okDuplicates + " 条。",
                            "CyberStrikeAI History", JOptionPane.INFORMATION_MESSAGE));
                } catch (Exception ex) {
                    callbacks.printError("CyberStrikeAI history sync error: " + ex.getMessage());
                    SwingUtilities.invokeLater(() -> JOptionPane.showMessageDialog(tab.getUiComponent(),
                            "同步失败: " + ex.getMessage(),
                            "CyberStrikeAI History", JOptionPane.ERROR_MESSAGE));
                } finally {
                    historySyncing.set(false);
                }
            }, "CyberStrikeAI-HistorySync");
            worker.start();
        } catch (Exception e) {
            historySyncing.set(false);
            callbacks.printError("CyberStrikeAI history sync error: " + e.getMessage());
        }
    }

    private void sendMessage(IHttpRequestResponse msg) {
        if (msg == null) return;
        CyberStrikeAIClient.Config cfg = tab.currentConfig();
        String token = tab.getToken();
        if (token == null || token.trim().isEmpty()) {
            JOptionPane.showMessageDialog(tab.getUiComponent(),
                    "Please click Validate first to obtain a token.",
                    "CyberStrikeAI", JOptionPane.WARNING_MESSAGE);
            return;
        }

        SendOptionsDialog.Result options = SendOptionsDialog.show(
                tab.getUiComponent(), client, cfg, token, lastInstruction);
        if (options == null) {
            return;
        }
        lastInstruction = options.instruction;

        String prompt = HttpMessageFormatter.toPrompt(helpers, msg, options.instruction);
        String title = HttpMessageFormatter.getRequestTitle(helpers, msg);
        String agentModeStr = options.agentMode.displayName;
        String roleLabel = options.role.isEmpty() ? "默认" : options.role;
        String runId = tab.startNewRun(title, agentModeStr + " · " + roleLabel, msg);
        tab.appendProgressToRun(runId, "\n[server] " + cfg.baseUrl);
        if (!options.projectId.isEmpty()) {
            tab.appendProgressToRun(runId, "\n[project] " + options.projectId);
        }
        tab.appendProgressToRun(runId, "\n\n");

        client.streamTest(cfg, token, prompt, options.role, options.projectId, options.agentMode,
                new CyberStrikeAIClient.StreamListener() {
            @Override
            public void onEvent(String type, String message, String rawJson) {
                if (type == null) type = "";
                switch (type) {
                    case "response_start":
                        tab.appendProgressToRun(runId, "\n\n[主回复]\n");
                        break;
                    case "response_delta":
                        if (message != null && !message.isEmpty()) {
                            tab.appendFinalToRun(runId, message);
                        }
                        break;
                    case "response":
                        tab.appendFinalToRun(runId, message);
                        tab.setFinalResponse(runId, message);
                        break;
                    case "eino_agent_reply_stream_start":
                        tab.appendProgressToRun(runId, "\n\n[子代理回复]\n");
                        break;
                    case "eino_agent_reply_stream_delta":
                        if (message != null && !message.isEmpty()) {
                            tab.appendProgressToRun(runId, message);
                        }
                        break;
                    case "eino_agent_reply_stream_end":
                        tab.appendProgressToRun(runId, "\n");
                        break;
                    case "eino_agent_reply":
                        if (message != null && !message.isEmpty()) {
                            tab.appendProgressToRun(runId, "\n\n[子代理回复]\n" + message + "\n");
                        }
                        break;
                    case "progress":
                        tab.appendProgressToRun(runId, "\n[progress] " + message + "\n");
                        tab.setRunStatus(runId, "running");
                        break;
                    case "cancelled":
                        tab.appendProgressToRun(runId, "\n[cancelled] " + message + "\n");
                        tab.setRunStatus(runId, "cancelled");
                        break;
                    case "error":
                        tab.appendProgressToRun(runId, "\n[error] " + message + "\n");
                        tab.setRunStatus(runId, "error");
                        break;
                    case "reasoning_chain_stream_start":
                        tab.appendProgressToRun(runId, "\n\n[推理过程]\n");
                        break;
                    case "reasoning_chain_stream_delta":
                        if (message != null && !message.isEmpty()) {
                            tab.appendProgressToRun(runId, message);
                        }
                        break;
                    case "reasoning_chain_stream_end":
                        tab.appendProgressToRun(runId, "\n");
                        break;
                    case "reasoning_chain":
                        if (message != null && !message.isEmpty()) {
                            String streamId = rawJson != null ? SimpleJson.extractStringField(rawJson, "streamId") : "";
                            if (streamId == null || streamId.isEmpty()) {
                                tab.appendProgressToRun(runId, "\n\n[推理过程]\n" + message + "\n");
                            }
                        }
                        break;
                    case "thinking_stream_start":
                        if (tab.isShowDebugEvents()) {
                            tab.resetThinkingStream(runId);
                        }
                        break;
                    case "thinking_stream_delta":
                        if (tab.isShowDebugEvents() && message != null && !message.isEmpty()) {
                            tab.appendProgressToRun(runId, message);
                        }
                        break;
                    case "tool_call":
                    case "tool_result":
                    case "tool_result_delta":
                        if (tab.isShowDebugEvents() && message != null && !message.isEmpty()) {
                            tab.appendProgressToRun(runId, "\n[" + type + "] " + message + "\n");
                        }
                        break;
                    case "conversation":
                        if (rawJson != null) {
                            String convId = SimpleJson.extractStringField(rawJson, "conversationId");
                            if (convId != null && !convId.trim().isEmpty()) {
                                tab.setRunConversationId(runId, convId);
                            }
                        }
                        if (tab.isShowDebugEvents() && message != null && !message.isEmpty()) {
                            tab.appendProgressToRun(runId, "\n[" + type + "] " + message + "\n");
                        }
                        break;
                    case "done":
                        break;
                    default:
                        if (tab.isShowDebugEvents() && message != null && !message.isEmpty()
                                && !type.endsWith("_stream_delta") && !type.endsWith("_stream_start")
                                && !type.endsWith("_stream_end")) {
                            tab.appendProgressToRun(runId, "\n[" + type + "] " + message + "\n");
                        }
                        break;
                }
            }

            @Override
            public void onError(String message, Exception e) {
                boolean cancelled = message != null && message.toLowerCase().contains("cancel");
                tab.appendProgressToRun(runId, cancelled ? "\n[info] " + message + "\n" : "\n[error] " + message + "\n");
                tab.setRunStatus(runId, cancelled ? "cancelled" : "error");
                callbacks.printError("CyberStrikeAI stream error: " + message);
                if (e != null) {
                    callbacks.printError(e.toString());
                }
            }

            @Override
            public void onDone() {
                tab.appendProgressToRun(runId, "\n\n[done]\n");
                tab.setRunStatus(runId, "done");
            }
        });
    }
}

