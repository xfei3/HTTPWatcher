package burp;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableModel;
import java.awt.*;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.regex.Pattern;

/*
* Project template is from https://t0data.gitbooks.io/burpsuite/content/chapter16.html
* Modified by Xiejingwei Fei
* This tool is for you to check if your website has CSRF vulnerability.
* I am not responsible for any malicious use.
* */
public class BurpExtender extends AbstractTableModel implements IBurpExtender,
		ITab, IMessageEditorController, IHttpListener {
	private IBurpExtenderCallbacks callbacks;
	private IExtensionHelpers helpers;
	private JSplitPane splitPane;
	private IMessageEditor requestViewer;
	private IMessageEditor responseViewer;
	private final List<LogEntry> log = new ArrayList<LogEntry>();
	private IHttpRequestResponse currentlyDisplayedItem;
	private boolean isOpen = true;// 插件是否生效
    public static final int VALUES_INIT_SIZE=5;

    private boolean isReqHeaderEnabled=false, isReqHeaderRegex=false;
    private boolean isReqBodyEnabled=false, isReqBodyRegex=false;
    private boolean isRespHeaderEnabled=false, isRespHeaderRegex=false;
    private boolean isRespBodyEnabled=false, isRespBodyRegex=false;
    private boolean hasJsonArray=true;

	private String Path_regex= ".*";

    private HashSet<String> reqHValues= new HashSet<String>(VALUES_INIT_SIZE);
    private HashSet<String> reqBValues= new HashSet<String>(VALUES_INIT_SIZE);
    private HashSet<String> respHValues= new HashSet<String>(VALUES_INIT_SIZE);
    private HashSet<String> respBValues= new HashSet<String>(VALUES_INIT_SIZE);


	@Override
	public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
		this.callbacks = callbacks;
		helpers = callbacks.getHelpers();
		callbacks.setExtensionName("HTTP Watcher"); // 插件名称
		// 开始创建自定义UI
		SwingUtilities.invokeLater(new Runnable() {
			@Override
			public void run() {
				// 主面板
				splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
				JTabbedPane topTabs = new JTabbedPane();
				// HistoryLog 视图
				Table logTable = new Table(BurpExtender.this);
				JScrollPane scrollPane = new JScrollPane(logTable);
				// 创建【options】显示面板
				JPanel optionsPanel = BurpExtender.this.createOptionsPanel();

				// 添加主面板的上半部分中，分两个tab页
				topTabs.add("Options", optionsPanel);
				topTabs.add("Suspicious requests", scrollPane);
				splitPane.setLeftComponent(topTabs);

				// request/response 视图
				JTabbedPane tabs = new JTabbedPane();
				requestViewer = callbacks.createMessageEditor(
						BurpExtender.this, false);
				responseViewer = callbacks.createMessageEditor(
						BurpExtender.this, false);

				// 添加主面板的下半部分中，分两个tab页
				tabs.addTab("Request", requestViewer.getComponent());
				tabs.addTab("Response", responseViewer.getComponent());
				splitPane.setRightComponent(tabs);

				// 自定义自己的组件
				callbacks.customizeUiComponent(splitPane);
				callbacks.customizeUiComponent(topTabs);
				callbacks.customizeUiComponent(tabs);

				// 在Burp添加自定义插件的tab页
				callbacks.addSuiteTab(BurpExtender.this);

				// 注册HTTP listener
				callbacks.registerHttpListener(BurpExtender.this);
			}
		});
	}

	@Override
	public void processHttpMessage(int toolFlag, boolean messageIsRequest,
								   IHttpRequestResponse messageInfo) {
		//如果插件未启用，则跳出不执行
		if (!isOpen)return;
		try {
			// 不同的toolflag代表了不同的burp组件，如INTRUDER,SCANNER,PROXY,SPIDER
			if (toolFlag == callbacks.TOOL_PROXY || toolFlag == callbacks.TOOL_INTRUDER
					|| toolFlag == callbacks.TOOL_SCANNER || toolFlag == callbacks.TOOL_SPIDER) {
				if (messageIsRequest) {//if you want to modify request, then do something here
//					IRequestInfo analyzeRequest = helpers
//							.analyzeRequest(messageInfo); // 对消息体进行解析
//					String request = new String(messageInfo.getRequest());
//					byte[] body = request.substring(
//							analyzeRequest.getBodyOffset()).getBytes();
//					//获取http请求头的信息，返回headers参数的列表
//					List<String> headers = analyzeRequest.getHeaders();


//					//根据IP生成方式,获取IP值
//					String ip ;
//					if(isAuto)
//						ip= this.getIpValue(true);
//					else
//						ip = this.getIpValue(false);
//					String xforward = "X-Forwarded-For: "+ ip;
//					//添加X-Forwarded-For
//					headers.add(xforward);

//
//					//重新组装请求消息
//					byte[] newRequest = helpers.buildHttpMessage(headers, body);
//					messageInfo.setRequest(newRequest);// 设置最终新的请求包
				}else {//modify response or you can check full request and response

					IRequestInfo analyzeRequest = helpers
							.analyzeRequest(messageInfo); // 对消息体进行解析
					String request = new String(messageInfo.getRequest());
					byte[] reqBody = request.substring(
							analyzeRequest.getBodyOffset()).getBytes();
					//获取http请求头的信息，返回headers参数的列表
					List<String> reqheaders = analyzeRequest.getHeaders();

                    IResponseInfo analyzeResponse=helpers.analyzeResponse(messageInfo.getResponse());
                    List<String> respheaders = analyzeResponse.getHeaders();
                    String response = new String(messageInfo.getResponse());
                    byte[] respBody = response.substring(
                            analyzeResponse.getBodyOffset()).getBytes();

					String url=analyzeRequest.getUrl().toString();
					boolean isMatch=Pattern.compile(Path_regex).matcher(url).matches(), record = false;

					if(!isMatch)
					{
						return;
					}

                    if(isReqHeaderEnabled&&reqheaders!=null)
                    {
                        if(isReqHeaderRegex)
                        {
                            for(String h: reqheaders)
                            {
                                Iterator<String> strs = reqHValues.iterator();
                                if(Pattern.compile(strs.next()).matcher(h).matches())//only one regex value
                                {
                                    record = true;
                                }
                            }
                        }else
                        {
                            for(String h: reqheaders)
                            {
                                Iterator<String> strs = reqHValues.iterator();
                                while(strs.hasNext())
                                {
                                    if(h.contains(strs.next()))
                                    {
                                        record = true;
                                    }
                                }

                            }
                        }
                    }

                    if(isReqBodyEnabled)
                    {
                        String tmpBody = "";
                        if (reqBody != null)
                        {
                            tmpBody = new String(reqBody);

                            if(isReqBodyRegex)
                            {
                                Iterator<String> strs = reqBValues.iterator();
                                if(Pattern.compile(strs.next()).matcher(tmpBody).matches())//only one regex value
                                {
                                    record = true;
                                }
                            }else
                            {
                                    Iterator<String> strs = reqBValues.iterator();
                                    while(strs.hasNext())
                                    {
                                        if(tmpBody.contains(strs.next()))
                                        {
                                            record = true;
                                        }
                                    }
                            }
                        }
                        tmpBody= null;
                    }


                    if(isRespHeaderEnabled&&respheaders!=null)
                    {
                        if(isRespHeaderRegex)
                        {
                            for(String h: respheaders)
                            {
                                Iterator<String> strs = respHValues.iterator();
                                if(Pattern.compile(strs.next()).matcher(h).matches())//only one regex value
                                {
                                    record = true;
                                }
                            }
                        }else
                        {
                            for(String h: respheaders)
                            {
                                    Iterator<String> strs = respHValues.iterator();
                                    while(strs.hasNext())
                                    {
                                        if(h.contains(strs.next()))
                                        {
                                            record = true;
                                        }
                                    }
                            }
                        }
                    }

                    if(isRespBodyEnabled)
                    {
                        String tmpBody = "";
                        if (respBody != null)
                        {
                            tmpBody = new String(respBody);
                            if(isRespBodyRegex)
                            {
                                Iterator<String> strs = respBValues.iterator();
                                if(Pattern.compile(strs.next()).matcher(tmpBody).matches())//only one regex value
                                {
                                    record = true;
                                }
                            }else
                            {
                                Iterator<String> strs = respBValues.iterator();
                                while(strs.hasNext())
                                {
                                    if(tmpBody.contains(strs.next()))
                                    {
                                        record = true;
                                    }
                                }
                            }
                        }
                        tmpBody= null;
                    }

                    if(hasJsonArray)
                    {
                        String tmpBody = "";
                        if (respBody != null) //body may be null, but also need to check url
                        {
                            tmpBody = new String(respBody).trim();
                            if(tmpBody.startsWith("[")&&tmpBody.endsWith("]"))
                            {
                                record = true;
                            }
                        }
                        tmpBody=null;
                    }

					if(!record)
					{
						return;
					}


					//添加消息到HistoryLog记录中，供UI显示用
					synchronized (log) {
						int row = log.size();
						short httpcode = helpers.analyzeResponse(
								messageInfo.getResponse()).getStatusCode();
						log.add(new LogEntry(toolFlag, callbacks
								.saveBuffersToTempFiles(messageInfo), helpers
								.analyzeRequest(messageInfo).getUrl(), httpcode));
						fireTableRowsInserted(row, row);
					}
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	/**
	 * 创建options视图对象主方法
	 * @return options 视图对象
	 * @author t0data 2016-11-18 下午5:51:45
	 */
	public JPanel createOptionsPanel() {
		final JPanel optionsPanel = new JPanel();
		optionsPanel.setLayout(new BoxLayout(optionsPanel, BoxLayout.Y_AXIS));
		//是否启用X-forward-For复选框
		final JCheckBox isOpenCheck = new JCheckBox("Enable plugin", true);
		//是否自动生成X-forward-For值单选按钮
//		final JRadioButton isAutoRadio = new JRadioButton("自动生成X-forward-For值",
//				true);
//		//是否指定X-forward-For值单选按钮
//		final JRadioButton isSpecifyRadio = new JRadioButton("指定X-forward-For值");
//		//指定IP值输入框和label
//		JLabel label = new JLabel("<html>&nbsp;&nbsp;&nbsp;&nbsp;Ip值：</html>");
//		final JTextField ipText = new JTextField("", 15);
//		ipText.setEditable(false);
//		ipText.setBackground(Color.WHITE);
//		//为复选框和单选按钮添加监听事件
		isOpenCheck.addItemListener(new ItemListener() {
			public void itemStateChanged(ItemEvent e) {
				if (isOpenCheck.isSelected()) {
					isOpen = true;
				} else {
					isOpen = false;
				}
			}
		});



		final JPanel opt0Panel = new JPanel();//is enabled
		opt0Panel.setLayout(new FlowLayout(FlowLayout.LEFT));

		final JPanel opt1Panel = new JPanel();//basic config
		opt1Panel.setLayout(new FlowLayout(FlowLayout.LEFT));

		final JPanel opt2Panel = new JPanel();//check value in request header
		opt2Panel.setLayout(new FlowLayout(FlowLayout.LEFT));

		final JPanel opt3Panel = new JPanel();//check value in request body
		opt3Panel.setLayout(new FlowLayout(FlowLayout.LEFT));

		final JPanel opt4Panel = new JPanel();//check value in response header
		opt4Panel.setLayout(new FlowLayout(FlowLayout.LEFT));

		final JPanel opt5Panel = new JPanel();//check value in response body
		opt5Panel.setLayout(new FlowLayout(FlowLayout.LEFT));


		opt0Panel.add(isOpenCheck);

		JLabel urlLabel = new JLabel("<html>URL regex:</html>");
		final JTextField regexText = new JTextField(Path_regex, 15);
        JCheckBox jsonArrayBx = new JCheckBox("JSON array response", true);
		opt1Panel.add(urlLabel);
		opt1Panel.add(regexText);
        opt1Panel.add(jsonArrayBx);

        regexText.getDocument().addDocumentListener(new DocumentListener() {
            public void changedUpdate(DocumentEvent e) {
                updateRegex();
            }
            public void removeUpdate(DocumentEvent e) {
                updateRegex();
            }
            public void insertUpdate(DocumentEvent e) {
                updateRegex();
            }

            public void updateRegex() {
                Path_regex=regexText.getText().trim();
            }
        });

        jsonArrayBx.addItemListener(new ItemListener() {
            public void itemStateChanged(ItemEvent e) {
                if (jsonArrayBx.isSelected()) {
                    hasJsonArray=true;
                } else {
                    hasJsonArray=false;
                }
            }
        });


		JLabel reqHeaderLabel = new JLabel("<html>Values in request header:</html>");
		final JTextField reqHeaderValues = new JTextField("", 15);
		JCheckBox enableReqHeader = new JCheckBox("Enable", false);
		JCheckBox reqHeaderRegex = new JCheckBox("isRegex", false);
		opt2Panel.add(reqHeaderLabel);
        opt2Panel.add(reqHeaderValues);
        reqHeaderValues.setEditable(false);
        reqHeaderValues.setBackground(Color.LIGHT_GRAY);
        opt2Panel.add(enableReqHeader);
        opt2Panel.add(reqHeaderRegex);

        enableReqHeader.addItemListener(new ItemListener() {
            public void itemStateChanged(ItemEvent e) {
                if (enableReqHeader.isSelected()) {
                    isReqHeaderEnabled = true;
                    reqHeaderValues.setEditable(true);
                    reqHeaderValues.setBackground(Color.WHITE);
                } else {
                    isReqHeaderEnabled = false;
                    reqHeaderValues.setEditable(false);
                    reqHeaderValues.setBackground(Color.LIGHT_GRAY);
                }
            }
        });

        reqHeaderRegex.addItemListener(new ItemListener() {
            public void itemStateChanged(ItemEvent e) {
                if (reqHeaderRegex.isSelected()) {
                    isReqHeaderRegex = true;
                } else {
                    isReqHeaderRegex = false;
                }
            }
        });

        reqHeaderValues.getDocument().addDocumentListener(new DocumentListener() {
            public void changedUpdate(DocumentEvent e) {
                updateRegex();
            }
            public void removeUpdate(DocumentEvent e) {
                updateRegex();
            }
            public void insertUpdate(DocumentEvent e) {
                updateRegex();
            }

            public void updateRegex() {
                reqHValues.clear();
                if(reqHeaderValues.getText().trim()=="")
                {
                    return;
                }
                if(isReqHeaderRegex){
                    reqHValues.add(reqHeaderValues.getText().trim());
                }
                else {
                    String[] hs = reqHeaderValues.getText().trim().split(",");
                    for(int i=0;hs!=null&&i<hs.length;i++)
                    {
                        reqHValues.add(hs[i]);
                    }
                }

            }
        });

		JLabel reqBodyLabel = new JLabel("<html>Values in request body:</html>");
		final JTextField reqBodyValues = new JTextField("", 15);
		JCheckBox enableReqBody = new JCheckBox("Enable", false);
		JCheckBox reqBodyRegex = new JCheckBox("isRegex", false);
		opt3Panel.add(reqBodyLabel);
        opt3Panel.add(reqBodyValues);
        reqBodyValues.setEditable(false);
        reqBodyValues.setBackground(Color.LIGHT_GRAY);
        opt3Panel.add(enableReqBody);
        opt3Panel.add(reqBodyRegex);

        enableReqBody.addItemListener(new ItemListener() {
            public void itemStateChanged(ItemEvent e) {
                if (enableReqBody.isSelected()) {
                    isReqBodyEnabled = true;
                    reqBodyValues.setEditable(true);
                    reqBodyValues.setBackground(Color.WHITE);
                } else {
                    isReqBodyEnabled = false;
                    reqBodyValues.setEditable(false);
                    reqBodyValues.setBackground(Color.LIGHT_GRAY);
                }
            }
        });

        reqBodyRegex.addItemListener(new ItemListener() {
            public void itemStateChanged(ItemEvent e) {
                if (reqBodyRegex.isSelected()) {
                    isReqBodyRegex = true;
                } else {
                    isReqBodyRegex = false;
                }
            }
        });

        reqBodyValues.getDocument().addDocumentListener(new DocumentListener() {
            public void changedUpdate(DocumentEvent e) {
                updateRegex();
            }
            public void removeUpdate(DocumentEvent e) {
                updateRegex();
            }
            public void insertUpdate(DocumentEvent e) {
                updateRegex();
            }

            public void updateRegex() {
                reqBValues.clear();
                if(reqBodyValues.getText().trim()=="")
                {
                    return;
                }
                if(isReqBodyRegex){
                    reqBValues.add(reqBodyValues.getText().trim());
                }
                else {
                    String[] hs = reqBodyValues.getText().trim().split(",");
                    for(int i=0;hs!=null&&i<hs.length;i++)
                    {
                        reqBValues.add(hs[i]);
                    }
                }
            }
        });

		JLabel respHeaderLabel = new JLabel("<html>Values in response header:</html>");
		final JTextField respHeaderValues = new JTextField("", 15);
		JCheckBox enablerespHeader = new JCheckBox("Enable", false);
		JCheckBox respHeaderRegex = new JCheckBox("isRegex", false);
		opt4Panel.add(respHeaderLabel);
        opt4Panel.add(respHeaderValues);
        respHeaderValues.setEditable(false);
        respHeaderValues.setBackground(Color.LIGHT_GRAY);
        opt4Panel.add(enablerespHeader);
        opt4Panel.add(respHeaderRegex);

        enablerespHeader.addItemListener(new ItemListener() {
            public void itemStateChanged(ItemEvent e) {
                if (enablerespHeader.isSelected()) {
                    isRespHeaderEnabled = true;
                    respHeaderValues.setEditable(true);
                    respHeaderValues.setBackground(Color.WHITE);
                } else {
                    isRespHeaderEnabled = false;
                    respHeaderValues.setEditable(false);
                    respHeaderValues.setBackground(Color.LIGHT_GRAY);
                }
            }
        });

        respHeaderRegex.addItemListener(new ItemListener() {
            public void itemStateChanged(ItemEvent e) {
                if (respHeaderRegex.isSelected()) {
                    isRespHeaderRegex = true;
                } else {
                    isRespHeaderRegex = false;
                }
            }
        });

        respHeaderValues.getDocument().addDocumentListener(new DocumentListener() {
            public void changedUpdate(DocumentEvent e) {
                updateRegex();
            }
            public void removeUpdate(DocumentEvent e) {
                updateRegex();
            }
            public void insertUpdate(DocumentEvent e) {
                updateRegex();
            }

            public void updateRegex() {
                respHValues.clear();
                if(respHeaderValues.getText().trim()=="")
                {
                    return;
                }
                if(isRespHeaderRegex){
                    respHValues.add(respHeaderValues.getText().trim());
                }
                else {
                    String[] hs = respHeaderValues.getText().trim().split(",");
                    for(int i=0;hs!=null&&i<hs.length;i++)
                    {
                        respHValues.add(hs[i]);
                    }
                }
            }
        });

		JLabel respBodyLabel = new JLabel("<html>Values in response body:</html>");
		final JTextField respBodyValues = new JTextField("", 15);
		JCheckBox enablerespBody = new JCheckBox("Enable", false);
		JCheckBox respBodyRegex = new JCheckBox("isRegex", false);
		opt5Panel.add(respBodyLabel);
        opt5Panel.add(respBodyValues);
        respBodyValues.setEditable(false);
        respBodyValues.setBackground(Color.LIGHT_GRAY);
        opt5Panel.add(enablerespBody);
        opt5Panel.add(respBodyRegex);

        enablerespBody.addItemListener(new ItemListener() {
            public void itemStateChanged(ItemEvent e) {
                if (enablerespBody.isSelected()) {
                    isRespBodyEnabled = true;
                    respBodyValues.setEditable(true);
                    respBodyValues.setBackground(Color.WHITE);
                } else {
                    isRespBodyEnabled = false;
                    respBodyValues.setEditable(false);
                    respBodyValues.setBackground(Color.LIGHT_GRAY);
                }
            }
        });

        respBodyRegex.addItemListener(new ItemListener() {
            public void itemStateChanged(ItemEvent e) {
                if (respBodyRegex.isSelected()) {
                    isRespBodyRegex = true;
                } else {
                    isRespBodyRegex = false;
                }
            }
        });

        respBodyValues.getDocument().addDocumentListener(new DocumentListener() {
            public void changedUpdate(DocumentEvent e) {
                updateRegex();
            }
            public void removeUpdate(DocumentEvent e) {
                updateRegex();
            }
            public void insertUpdate(DocumentEvent e) {
                updateRegex();
            }

            public void updateRegex() {
                respBValues.clear();
                if(respBodyValues.getText().trim()=="")
                {
                    return;
                }
                if(isRespBodyRegex){
                    respBValues.add(respBodyValues.getText().trim());
                }
                else {
                    String[] hs = respBodyValues.getText().trim().split(",");
                    for(int i=0;hs!=null&&i<hs.length;i++)
                    {
                        respBValues.add(hs[i]);
                    }
                }
            }
        });

		optionsPanel.add(opt0Panel);
		optionsPanel.add(opt1Panel);
		optionsPanel.add(opt2Panel);
		optionsPanel.add(opt3Panel);
		optionsPanel.add(opt4Panel);
		optionsPanel.add(opt5Panel);

		return optionsPanel;
	}

	@Override
	public String getTabCaption() {
		return "Http Watcher";
	}

	@Override
	public Component getUiComponent() {
		return splitPane;
	}

	@Override
	public int getRowCount() {
		return log.size();
	}

	@Override
	public int getColumnCount() {
		return 3;
	}

	@Override
	public String getColumnName(int columnIndex) {
		switch (columnIndex) {
			case 0:
				return "Tool";
			case 1:
				return "URL";
			case 2:
				return "STATUS";
			default:
				return "";
		}
	}

	@Override
	public Class<?> getColumnClass(int columnIndex) {
		return String.class;
	}

	@Override
	public Object getValueAt(int rowIndex, int columnIndex) {
		LogEntry logEntry = log.get(rowIndex);

		switch (columnIndex) {
			case 0:
				return callbacks.getToolName(logEntry.tool);
			case 1:
				return logEntry.url.toString();
			case 2:
				return logEntry.httpCode;
			default:
				return "";
		}
	}

	//
	// implement IMessageEditorController
	// this allows our request/response viewers to obtain details about the
	// messages being displayed
	//

	@Override
	public byte[] getRequest() {
		return currentlyDisplayedItem.getRequest();
	}

	@Override
	public byte[] getResponse() {
		return currentlyDisplayedItem.getResponse();
	}

	@Override
	public IHttpService getHttpService() {
		return currentlyDisplayedItem.getHttpService();
	}

	//
	// extend JTable to handle cell selection
	//

	private class Table extends JTable {
		public Table(TableModel tableModel) {
			super(tableModel);
		}

		@Override
		public void changeSelection(int row, int col, boolean toggle,
									boolean extend) {
			// show the log entry for the selected row
			LogEntry logEntry = log.get(row);
			requestViewer.setMessage(logEntry.requestResponse.getRequest(),
					true);
			responseViewer.setMessage(logEntry.requestResponse.getResponse(),
					false);
			currentlyDisplayedItem = logEntry.requestResponse;
			super.changeSelection(row, col, toggle, extend);
		}
	}

	//
	// class to hold details of each log entry
	//

	private static class LogEntry {
		final int tool;
		final IHttpRequestResponsePersisted requestResponse;
		final URL url;
		final short httpCode;

		LogEntry(int tool, IHttpRequestResponsePersisted requestResponse,
				 URL url, short httpCode) {
			this.tool = tool;
			this.requestResponse = requestResponse;
			this.url = url;
			this.httpCode = httpCode;
		}
	}
}