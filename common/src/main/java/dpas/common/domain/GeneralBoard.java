package dpas.common.domain;

import dpas.common.domain.exception.NullPostException;
import dpas.common.domain.exception.NullUserException;
import dpas.common.domain.exception.InvalidNumberOfPostsException;
import java.util.ArrayList;

public class GeneralBoard implements AnnouncementBoard {
    public ArrayList<Announcement> posts;

    @Override

    public void post(User user, Announcement announcement) throws NullPostException, NullUserException {
         checkArguments(user, announcement);
        posts.add(announcement);
    }

    public void checkArguments(User user, Announcement post) throws NullUserException, NullPostException  {
        if (user == null) {
            throw new NullUserException();
        }
        if (post == null) {
            throw new NullPostException();
        }
    }

    //FIXME maybe if number > posts.size() just return all of the posts? If number is zero return all posts (from the assignment)
    @Override
    public Announcement[] read(int number) throws InvalidNumberOfPostsException {
        if (number <= 0 || number > posts.size())
            throw new InvalidNumberOfPostsException();
        return (Announcement[]) posts.subList(posts.size()-number, posts.size()).toArray();
    }
}
