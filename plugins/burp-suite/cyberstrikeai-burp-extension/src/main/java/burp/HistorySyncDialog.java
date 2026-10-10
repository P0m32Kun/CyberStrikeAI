package burp;

import javax.swing.*;
import java.awt.*;
import java.util.List;

/**
 * 「Send to CyberStrikeAI History」确认对话框：选项目 + 显示将同步的条目数。
 * 项目列表复用 CyberStrikeAIClient.fetchProjects，默认选中与送测对话框共享的上次选择。
 */
final class HistorySyncDialog {
    private HistorySyncDialog() {}

    static final class Result {
        final String projectId;

        Result(String projectId) {
            this.projectId = projectId == null ? "" : projectId;
        }
    }

    static Result show(
            Component parent,
            CyberStrikeAIClient client,
            CyberStrikeAIClient.Config cfg,
            String token,
            int flowCount
    ) {
        JPanel panel = new JPanel(new BorderLayout(0, 10));
        panel.setBorder(BorderFactory.createEmptyBorder(4, 4, 0, 4));

        JLabel info = new JLabel("将同步 " + flowCount + " 条流量到 CyberStrikeAI History（source=burp）。");
        JComboBox<CyberStrikeAIClient.ProjectOption> projectBox = new JComboBox<>();
        projectBox.addItem(new CyberStrikeAIClient.ProjectOption("", "加载中..."));
        projectBox.setEnabled(false);

        JPanel selectors = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        selectors.add(new JLabel("项目"));
        selectors.add(projectBox);

        panel.add(info, BorderLayout.NORTH);
        panel.add(selectors, BorderLayout.CENTER);

        Thread loader = new Thread(() -> {
            try {
                List<CyberStrikeAIClient.ProjectOption> projects = client.fetchProjects(cfg, token);
                SwingUtilities.invokeLater(() -> {
                    projectBox.removeAllItems();
                    for (CyberStrikeAIClient.ProjectOption item : projects) {
                        projectBox.addItem(item);
                    }
                    String last = SendOptionsDialog.lastProjectId();
                    boolean matched = false;
                    for (int i = 0; i < projectBox.getItemCount(); i++) {
                        CyberStrikeAIClient.ProjectOption item = projectBox.getItemAt(i);
                        if (item != null && item.id.equals(last)) {
                            projectBox.setSelectedIndex(i);
                            matched = true;
                            break;
                        }
                    }
                    if (!matched && projectBox.getItemCount() > 0) {
                        projectBox.setSelectedIndex(0);
                    }
                    projectBox.setEnabled(true);
                });
            } catch (Exception ex) {
                SwingUtilities.invokeLater(() -> {
                    projectBox.removeAllItems();
                    projectBox.addItem(new CyberStrikeAIClient.ProjectOption("", "(加载失败)"));
                    projectBox.setEnabled(true);
                    JOptionPane.showMessageDialog(parent,
                            "加载项目失败: " + ex.getMessage(),
                            "CyberStrikeAI", JOptionPane.WARNING_MESSAGE);
                });
            }
        }, "CyberStrikeAI-LoadProjects");
        loader.start();

        int result = JOptionPane.showConfirmDialog(
                parent,
                panel,
                "同步到 CyberStrikeAI History",
                JOptionPane.OK_CANCEL_OPTION,
                JOptionPane.PLAIN_MESSAGE
        );
        if (result != JOptionPane.OK_OPTION) {
            return null;
        }

        CyberStrikeAIClient.ProjectOption project = (CyberStrikeAIClient.ProjectOption) projectBox.getSelectedItem();
        String projectId = project != null ? project.id : "";
        SendOptionsDialog.rememberProjectId(projectId);
        return new Result(projectId);
    }
}
