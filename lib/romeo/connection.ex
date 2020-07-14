defmodule Romeo.Connection do
  @moduledoc false

  @timeout 5_000
  @connect_retry_backoff_default 5_000
  @connect_retry_backoff_max 300_000
  @default_transport Romeo.Transports.TCP

  alias Romeo.Connection.Features

  defstruct component: false,
            features: %Features{},
            host: nil,
            jid: nil,
            legacy_tls: false,
            nickname: "",
            owner: nil,
            parser: nil,
            password: nil,
            port: nil,
            preferred_auth_mechanisms: [],
            require_tls: false,
            resource: "",
            rooms: [],
            ssl_opts: [],
            socket: nil,
            socket_opts: [],
            stream_id: nil,
            timeout: nil,
            connect_retry_backoff: @connect_retry_backoff_default,
            transport: nil

  use Connection

  require Logger

  ### PUBLIC API ###

  @doc """
  Start the connection process and connect to an XMPP server.

  ## Options

    * `:component` - Connect as an [XMPP Component][0] (default: `false`);
    * `:host` - Server hostname (default: inferred by the JID);
    * `:jid` - User jabber ID;
    * `:password` - User password;
    * `:port` - Server port (default: based on the transport);
    * `:require_tls` - Set to `false` if ssl should not be used (default: `true`);
    * `:ssl_opts` - A list of ssl options, see ssl docs;
    * `:socket_opts` - Options to be given to the underlying socket;
    * `:timeout` - Connect timeout in milliseconds (default: `#{@timeout}`);
    * `:transport` - Transport handles the protocol (default: `#{@default_transport}`);

  [0]: http://xmpp.org/extensions/xep-0114.html
  """
  def start_link(args, options \\ []) do
    args =
      args
      |> Keyword.put_new(:timeout, @timeout)
      |> Keyword.put_new(:transport, @default_transport)
      |> Keyword.put_new(:owner, self())

    Connection.start_link(__MODULE__, {struct(__MODULE__, args), self()}, options)
  end

  @doc """
  Send a message via the underlying transport.
  """
  def send(pid, data) do
    Connection.call(pid, {:send, data})
  end

  @doc """
  Stop the process and disconnect.

  ## Options

    * `:timeout` - Call timeout (default: `#{@timeout}`)
  """
  @spec close(pid, Keyword.t()) :: :ok
  def close(pid, opts \\ []) do
    Connection.call(pid, :close, opts[:timeout] || @timeout)
  end

  ## Connection callbacks

  def init({conn, caller}) do
    if conn.owner != caller do
      Process.monitor(conn.owner)
    end

    {:connect, :init, conn}
  end

  def connect(_, %{transport: transport, connect_retry_backoff: connect_retry_backoff} = conn) do
    case transport.connect(conn) do
      {:ok, conn} ->
        {:ok, conn}

      {:error, _} = error ->
        connect_retry_backoff =
          :backoff.rand_increment(connect_retry_backoff, @connect_retry_backoff_max)

        Logger.warn(fn ->
          "Connecting failed, retrying in #{connect_retry_backoff} ms.\nFull error: #{
            inspect(error)
          }"
        end)

        {:backoff, connect_retry_backoff, %{conn | connect_retry_backoff: connect_retry_backoff}}
    end
  end

  def disconnect({:close, from}, %{socket: socket, transport: transport} = conn) do
    transport.disconnect({:close, from}, socket)
    {:stop, {:shutdown, :closed}, conn}
  end

  def disconnect({:owner_down, reason}, %{socket: socket, transport: transport} = conn) do
    transport.disconnect({:owner_down, reason}, socket)
    {:stop, {:shutdown, {:owner_down, reason}}, conn}
  end

  def disconnect(info, %{socket: socket, transport: transport} = conn) do
    transport.disconnect(info, socket)
    {:connect, :reconnect, reset_connection(conn)}
  end

  defp reset_connection(conn) do
    %{conn | features: %Features{}, parser: nil, socket: nil}
  end

  def handle_call(_, _, %{socket: nil} = conn) do
    {:reply, {:error, :closed}, conn}
  end

  def handle_call({:send, data}, _, %{transport: transport} = conn) do
    case transport.send(conn, data) do
      {:ok, conn} ->
        {:reply, :ok, conn}

      {:error, _} = error ->
        {:disconnect, error, error, conn}
    end
  end

  def handle_call(:close, from, %{socket: socket, transport: transport} = conn) do
    transport.disconnect({:close, from}, socket)
    {:reply, :ok, conn}
  end

  def handle_info({:DOWN, _, :process, owner, reason}, %{owner: owner} = conn) do
    {:disconnect, {:owner_down, reason}, conn}
  end

  def handle_info(info, %{owner: owner, transport: transport} = conn) do
    case transport.handle_message(info, conn) do
      {:ok, conn, :more} ->
        {:noreply, conn}

      {:ok, conn, stanza} ->
        stanza = Romeo.Stanza.Parser.parse(stanza)
        Kernel.send(owner, {:stanza, stanza, self()})
        {:noreply, conn}

      {:error, _} = error ->
        {:disconnect, error, conn}

      :unknown ->
        Logger.debug(fn ->
          [inspect(__MODULE__), ?\s, inspect(self()), " received message: " | inspect(info)]
        end)

        {:noreply, conn}
    end
  end
end
