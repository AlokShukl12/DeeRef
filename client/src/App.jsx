import { useCallback, useEffect, useRef, useState } from 'react';
import { io } from 'socket.io-client';
import './App.css';

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:5000/api';
const WS_URL = import.meta.env.VITE_WS_URL || 'http://localhost:5000';

function App() {
  const [token, setToken] = useState(localStorage.getItem('token'));
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    async function fetchUser() {
      if (!token) {
        setLoading(false);
        return;
      }
      try {
        const res = await fetch(`${API_URL}/auth/me`, {
          headers: { Authorization: `Bearer ${token}` },
        });
        if (!res.ok) throw new Error('Session expired, please sign in again.');
        const data = await res.json();
        setUser(data.user);
        setError('');
      } catch (err) {
        setError(err.message);
        handleLogout();
      } finally {
        setLoading(false);
      }
    }
    fetchUser();
  }, [token]);

  const handleAuth = ({ user: nextUser, token: nextToken }) => {
    localStorage.setItem('token', nextToken);
    setToken(nextToken);
    setUser(nextUser);
    setError('');
  };

  const handleLogout = () => {
    localStorage.removeItem('token');
    setToken(null);
    setUser(null);
  };

  if (loading) {
    return (
      <div className="screen">
        <div className="card loading">Loading...</div>
      </div>
    );
  }

  if (!token || !user) {
    return (
      <div className="screen">
        <AuthForm onAuth={handleAuth} error={error} />
      </div>
    );
  }

  return (
    <div className="screen">
      <ChatPage token={token} user={user} onLogout={handleLogout} globalError={error} />
    </div>
  );
}

function AuthForm({ onAuth, error }) {
  const [mode, setMode] = useState('login');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [pending, setPending] = useState(false);
  const [message, setMessage] = useState(error || '');

  const handleSubmit = async (e) => {
    e.preventDefault();
    setPending(true);
    setMessage('');
    try {
      const res = await fetch(`${API_URL}/auth/${mode}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.message || 'Something went wrong');
      onAuth(data);
    } catch (err) {
      setMessage(err.message);
    } finally {
      setPending(false);
    }
  };

  return (
    <div className="card auth-card">
      <h1>Team Chat</h1>
      <p className="muted">Create an account or sign in to continue.</p>
      <form onSubmit={handleSubmit} className="stack">
        <label className="stack">
          <span>Username</span>
          <input value={username} onChange={(e) => setUsername(e.target.value)} required />
        </label>
        <label className="stack">
          <span>Password</span>
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} required />
        </label>
        {message && <div className="error">{message}</div>}
        <button type="submit" disabled={pending}>
          {pending ? 'Please wait...' : mode === 'login' ? 'Log in' : 'Create account'}
        </button>
      </form>
      <div className="muted switch">
        {mode === 'login' ? (
          <span>
            Need an account?{' '}
            <button className="link" onClick={() => setMode('register')}>
              Register
            </button>
          </span>
        ) : (
          <span>
            Already registered?{' '}
            <button className="link" onClick={() => setMode('login')}>
              Log in
            </button>
          </span>
        )}
      </div>
    </div>
  );
}

function ChatPage({ token, user, onLogout, globalError }) {
  const [channels, setChannels] = useState([]);
  const [selectedChannel, setSelectedChannel] = useState(null);
  const [messages, setMessages] = useState([]);
  const [nextCursor, setNextCursor] = useState(null);
  const [onlineUsers, setOnlineUsers] = useState([]);
  const [socket, setSocket] = useState(null);
  const [channelError, setChannelError] = useState(globalError || '');
  const [loadingMessages, setLoadingMessages] = useState(false);

  const selectedRef = useRef(null);

  const authFetch = useCallback(
    (path, options = {}) => {
      const headers = {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
        ...(options.headers || {}),
      };
      return fetch(`${API_URL}${path}`, { ...options, headers });
    },
    [token]
  );

  const loadChannels = useCallback(async () => {
    try {
      const res = await authFetch('/channels');
      const data = await res.json();
      if (!res.ok) throw new Error(data.message || 'Failed to load channels');
      setChannels(data.channels);
      if (!selectedRef.current && data.channels.length) {
        const initial = data.channels.find((c) => c.isMember) || data.channels[0];
        setSelectedChannel(initial);
      }
      setChannelError('');
      return data.channels;
    } catch (err) {
      setChannelError(err.message);
      return [];
    }
  }, [authFetch]);

  useEffect(() => {
    loadChannels();
  }, [loadChannels]);

  useEffect(() => {
    const s = io(WS_URL, { auth: { token } });
    setSocket(s);
    s.on('connect_error', (err) => setChannelError(err.message));
    return () => {
      s.disconnect();
      setSocket(null);
    };
  }, [token]);

  useEffect(() => {
    if (!socket) return;
    const handlePresence = (list) => setOnlineUsers(list);
    const handleMessage = (msg) => {
      if (msg.channel === selectedRef.current) {
        setMessages((prev) => [...prev, msg]);
      }
    };
    socket.on('presence:update', handlePresence);
    socket.on('message:new', handleMessage);
    return () => {
      socket.off('presence:update', handlePresence);
      socket.off('message:new', handleMessage);
    };
  }, [socket]);

  useEffect(() => {
    selectedRef.current = selectedChannel?._id || null;
  }, [selectedChannel]);

  useEffect(() => {
    if (!socket || !selectedChannel?.isMember) return;
    socket.emit('joinChannel', selectedChannel._id);
    return () => {
      if (selectedChannel?.isMember) {
        socket.emit('leaveChannel', selectedChannel._id);
      }
    };
  }, [socket, selectedChannel]);

  const fetchMessages = useCallback(
    async (channelId, cursor, append = false) => {
      if (!channelId) return;
      setLoadingMessages(true);
      try {
        const res = await authFetch(
          `/channels/${channelId}/messages?limit=20${cursor ? `&before=${encodeURIComponent(cursor)}` : ''}`
        );
        const data = await res.json();
        if (!res.ok) throw new Error(data.message || 'Failed to load messages');
        setMessages((prev) => (append ? [...data.messages, ...prev] : data.messages));
        setNextCursor(data.nextCursor);
        setChannelError('');
      } catch (err) {
        setChannelError(err.message);
      } finally {
        setLoadingMessages(false);
      }
    },
    [authFetch]
  );

  useEffect(() => {
    if (selectedChannel?.isMember) {
      fetchMessages(selectedChannel._id);
    } else {
      setMessages([]);
      setNextCursor(null);
    }
  }, [selectedChannel, fetchMessages]);

  const handleCreateChannel = async (name) => {
    try {
      const res = await authFetch('/channels', { method: 'POST', body: JSON.stringify({ name }) });
      const data = await res.json();
      if (!res.ok) throw new Error(data.message || 'Failed to create channel');
      setChannels((prev) => [...prev, data.channel]);
      setSelectedChannel(data.channel);
    } catch (err) {
      setChannelError(err.message);
    }
  };

  const handleJoin = async (channel) => {
    try {
      const res = await authFetch(`/channels/${channel._id}/join`, { method: 'POST' });
      if (!res.ok) {
        const data = await res.json();
        throw new Error(data.message || 'Failed to join channel');
      }
      const updated = await loadChannels();
      const refreshed = updated.find((c) => c._id === channel._id) || channel;
      setSelectedChannel({ ...refreshed, isMember: true });
    } catch (err) {
      setChannelError(err.message);
    }
  };

  const handleLeave = async (channel) => {
    try {
      const res = await authFetch(`/channels/${channel._id}/leave`, { method: 'POST' });
      if (!res.ok) {
        const data = await res.json();
        throw new Error(data.message || 'Failed to leave channel');
      }
      await loadChannels();
      setSelectedChannel(null);
      setMessages([]);
    } catch (err) {
      setChannelError(err.message);
    }
  };

  const handleSend = (content) => {
    if (!socket || !selectedChannel) return;
    socket.emit('message:create', { channelId: selectedChannel._id, content }, (resp) => {
      if (resp?.error) setChannelError(resp.error);
    });
  };

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="sidebar-header">
          <div>
            <p className="muted">Signed in as</p>
            <strong>{user.username}</strong>
          </div>
          <button className="ghost" onClick={onLogout}>
            Log out
          </button>
        </div>
        <CreateChannelForm onCreate={handleCreateChannel} />
        <ChannelList
          channels={channels}
          selectedId={selectedChannel?._id}
          onSelect={setSelectedChannel}
          onJoin={handleJoin}
          onLeave={handleLeave}
        />
      </aside>
      <main className="chat">
        <header className="chat-header">
          <div>
            <p className="muted">Channel</p>
            <h2>{selectedChannel ? `#${selectedChannel.name}` : 'Choose a channel'}</h2>
          </div>
          <span className="tag">{onlineUsers.length} online</span>
        </header>
        {channelError && <div className="error banner">{channelError}</div>}
        {selectedChannel ? (
          <>
            {selectedChannel.isMember ? (
              <>
                <MessageList
                  messages={messages}
                  onLoadMore={() => fetchMessages(selectedChannel._id, nextCursor, true)}
                  hasMore={Boolean(nextCursor)}
                  loading={loadingMessages}
                  currentUser={user}
                />
                <MessageInput onSend={handleSend} disabled={!selectedChannel?.isMember} />
              </>
            ) : (
              <div className="empty-state">Join this channel to view and send messages.</div>
            )}
          </>
        ) : (
          <div className="empty-state">Select or create a channel to start chatting.</div>
        )}
      </main>
      <aside className="presence">
        <PresenceList users={onlineUsers} />
      </aside>
    </div>
  );
}

function CreateChannelForm({ onCreate }) {
  const [name, setName] = useState('');
  const [pending, setPending] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!name.trim()) return;
    setPending(true);
    await onCreate(name.trim());
    setName('');
    setPending(false);
  };

  return (
    <form className="stack create-form" onSubmit={handleSubmit}>
      <label className="muted small">Create channel</label>
      <div className="input-row">
        <input value={name} onChange={(e) => setName(e.target.value)} placeholder="team-updates" />
        <button type="submit" disabled={pending}>
          {pending ? '...' : 'Create'}
        </button>
      </div>
    </form>
  );
}

function ChannelList({ channels, selectedId, onSelect, onJoin, onLeave }) {
  return (
    <div className="channel-list">
      <div className="muted small">Channels</div>
      <div className="channel-scroll">
        {channels.map((channel) => {
          const isSelected = selectedId === channel._id;
          return (
            <div key={channel._id} className={`channel ${isSelected ? 'active' : ''}`} onClick={() => onSelect(channel)}>
              <div>
                <div className="channel-name">#{channel.name}</div>
                <div className="muted tiny">{channel.membersCount} member(s)</div>
              </div>
              {channel.isMember ? (
                <button
                  className="ghost small"
                  onClick={(e) => {
                    e.stopPropagation();
                    onLeave(channel);
                  }}
                >
                  Leave
                </button>
              ) : (
                <button
                  className="ghost small"
                  onClick={(e) => {
                    e.stopPropagation();
                    onJoin(channel);
                  }}
                >
                  Join
                </button>
              )}
            </div>
          );
        })}
        {!channels.length && <div className="muted tiny">No channels yet.</div>}
      </div>
    </div>
  );
}

function MessageList({ messages, onLoadMore, hasMore, loading, currentUser }) {
  const listRef = useRef(null);

  useEffect(() => {
    if (listRef.current) {
      listRef.current.scrollTop = listRef.current.scrollHeight;
    }
  }, [messages.length]);

  return (
    <div className="message-panel">
      <div className="message-header">
        {hasMore ? (
          <button className="ghost small" onClick={onLoadMore} disabled={loading}>
            {loading ? 'Loading...' : 'Load older messages'}
          </button>
        ) : (
          <span className="muted tiny">Beginning of history</span>
        )}
      </div>
      <div className="message-list" ref={listRef}>
        {messages.map((msg) => {
          const mine = msg.sender._id === currentUser._id;
          return (
            <div key={msg._id} className={`message ${mine ? 'mine' : ''}`}>
              <div className="message-meta">
                <strong>{msg.sender.username}</strong>
                <span className="muted tiny">{new Date(msg.createdAt).toLocaleTimeString()}</span>
              </div>
              <p>{msg.content}</p>
            </div>
          );
        })}
        {!messages.length && <div className="muted tiny">No messages yet.</div>}
      </div>
    </div>
  );
}

function MessageInput({ onSend, disabled }) {
  const [value, setValue] = useState('');

  const handleSubmit = (e) => {
    e.preventDefault();
    if (!value.trim()) return;
    onSend(value);
    setValue('');
  };

  return (
    <form className="composer" onSubmit={handleSubmit}>
      <input
        value={value}
        onChange={(e) => setValue(e.target.value)}
        placeholder="Type a message..."
        disabled={disabled}
      />
      <button type="submit" disabled={disabled || !value.trim()}>
        Send
      </button>
    </form>
  );
}

function PresenceList({ users }) {
  return (
    <div className="presence-panel">
      <div className="muted small">Online</div>
      <div className="presence-list">
        {users.map((user) => (
          <div className="presence-item" key={user._id}>
            <span className="status-dot" /> {user.username}
          </div>
        ))}
        {!users.length && <div className="muted tiny">No one online.</div>}
      </div>
    </div>
  );
}

export default App;
