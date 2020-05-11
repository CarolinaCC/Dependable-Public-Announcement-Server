package dpas.common.domain;

import dpas.common.domain.exception.InvalidNumberOfPostsException;
import dpas.common.domain.exception.NullAnnouncementException;

import java.util.*;
import java.util.stream.Collectors;

public class GeneralBoard implements AnnouncementBoard {
    private static final Comparator<Announcement> GENERAL_BOARD_COMPARATOR = (a, b) ->
    {
        if (a.getSeq() != b.getSeq())
            return  b.getSeq() - a.getSeq();
        else {
            return Base64.getEncoder().encodeToString(b.getUser().getPublicKey().getEncoded())
                    .compareTo(Base64.getEncoder().encodeToString(a.getUser().getPublicKey().getEncoded()));
        }
    };
    public static final String GENERAL_BOARD_IDENTIFIER = "DPAS-GENERAL-BOARD";

    private final SortedSet<Announcement> posts = Collections.synchronizedSortedSet(new TreeSet<>(GENERAL_BOARD_COMPARATOR));

    @Override
    public void post(Announcement announcement) throws NullAnnouncementException {
        if (announcement == null) {
            throw new NullAnnouncementException("Invalid Announcement: Cannot be null");
        }
        this.posts.add(announcement);
    }

    @Override
    public List<Announcement> read(int number) throws InvalidNumberOfPostsException {
        if (number < 0) {
            throw new InvalidNumberOfPostsException("Invalid number of posts to read: number cannot be negative");
        }
        int size = number == 0 ? this.posts.size() : Math.min(this.posts.size(), number);
        List<Announcement> announcements;
        synchronized (this.posts) {
            announcements = this.posts.stream().limit(size).collect(Collectors.toList());
        }
        Collections.reverse(announcements);
        return announcements;
    }

    @Override
    public long getSeq() {
        if (this.posts.size() == 0) {
            return 0;
        }
        return this.posts.first().getSeq();
    }

    @Override
    public String getIdentifier() {
        return GENERAL_BOARD_IDENTIFIER;
    }

}
