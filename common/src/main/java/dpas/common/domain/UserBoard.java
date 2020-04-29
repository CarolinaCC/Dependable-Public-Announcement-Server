package dpas.common.domain;

import dpas.common.domain.exception.InvalidNumberOfPostsException;
import dpas.common.domain.exception.InvalidUserException;
import dpas.common.domain.exception.NullAnnouncementException;
import dpas.common.domain.exception.NullUserException;

import java.security.PublicKey;
import java.util.*;

public class UserBoard implements AnnouncementBoard {
    private final User owner;
    protected PublicKey publicKey;

    private final SortedSet<Announcement> posts = Collections.synchronizedSortedSet(new TreeSet<>(Comparator.comparing(Announcement::getSeq)));

    public UserBoard(User user) throws NullUserException {
        if (user == null)
            throw new NullUserException("Invalid User: Cannot be null");
        this.owner = user;
        this.publicKey = user.getPublicKey();
    }

    @Override
    public void post(Announcement announcement) throws NullAnnouncementException, InvalidUserException {
        checkArguments(announcement);
        this.posts.add(announcement);
    }

    private void checkArguments(Announcement post) throws NullAnnouncementException, InvalidUserException {
        if (post == null) {
            throw new NullAnnouncementException("Invalid Post: Cannot be null");
        }
        if (!post.getUser().equals(this.owner)) {
            throw new InvalidUserException("Invalid User: User is not owner of this board");
        }
    }

    public List<Announcement> read(int number) throws InvalidNumberOfPostsException {
        if (number < 0)
            throw new InvalidNumberOfPostsException("Invalid number of posts to read: number cannot be negative");
        List<Announcement> posts;
        synchronized (this.posts) {
            posts = new ArrayList<>(this.posts);
        }
        if (number == 0 || number >= posts.size())
            return posts;
        return posts.subList(posts.size() - number, posts.size());
    }

    @Override
    public long getSeq() {
        if (this.posts.size() == 0) {
            return 0;
        }
        return this.posts.last().getSeq();
    }

    @Override
    public String getIdentifier() {
        return Base64.getEncoder().encodeToString(this.publicKey.getEncoded());
    }

}
