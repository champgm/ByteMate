package bytemate;

import java.io.Serializable;

/**
 * Represents a single chat message in the conversation.
 */
public class ChatMessage implements Serializable {
    private static final long serialVersionUID = 1L;
    
    private String sender;
    private String message;
    private long timestamp;
    
    /**
     * Constructs a new chat message.
     * 
     * @param sender The sender of the message (User, Assistant, System)
     * @param message The message content
     */
    public ChatMessage(String sender, String message) {
        this.sender = sender;
        this.message = message;
        this.timestamp = System.currentTimeMillis();
    }
    
    /**
     * Gets the sender of the message.
     * 
     * @return The sender (User, Assistant, System)
     */
    public String getSender() {
        return sender;
    }
    
    /**
     * Gets the message content.
     * 
     * @return The message content
     */
    public String getMessage() {
        return message;
    }
    
    /**
     * Gets the timestamp when the message was created.
     * 
     * @return The timestamp in milliseconds
     */
    public long getTimestamp() {
        return timestamp;
    }
    
    /**
     * Sets the sender of the message.
     * 
     * @param sender The sender to set
     */
    public void setSender(String sender) {
        this.sender = sender;
    }
    
    /**
     * Sets the message content.
     * 
     * @param message The message content to set
     */
    public void setMessage(String message) {
        this.message = message;
    }
} 
